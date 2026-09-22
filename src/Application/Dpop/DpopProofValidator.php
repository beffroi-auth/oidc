<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Dpop;

use DateInterval;
use DateTimeImmutable;
use function hash;
use function hash_equals;
use Heidi\Oidc\Domain\Dpop\DpopProof;
use Heidi\Oidc\Domain\Token\Base64Url;
use Heidi\Oidc\Domain\Token\KeyConfirmation;
use Heidi\Oidc\Exception\InvalidDpopProofException;
use Heidi\Oidc\Exception\UseDpopNonceException;
use Heidi\Oidc\Port\DpopNonceInterface;
use Heidi\Oidc\Port\DpopProofReplayGuardInterface;
use SensitiveParameter;
use function sprintf;
use function strstr;

/**
 * What a proof has to say once the key it carries has been shown to have signed it (RFC 9449 §4.3).
 *
 * It says which request it was made for, and this is the whole point: a proof is not a credential the
 * holder of the key hands out, it is a signature over one request. The method and the URL are compared
 * with the endpoint that received it, as the provider publishes that endpoint and never as a header of
 * the request says it (§11.1); the "iat" keeps a proof to the window a request needs; the "jti" is
 * remembered for that window, so that a proof taken off the wire cannot be sent again; and the "ath"
 * ties the proof to the very access token the request carries, so that a proof cannot be moved from one
 * token to another.
 */
final readonly class DpopProofValidator
{
    /**
     * @param DateInterval $maximumAge how long a proof stands, from its "iat"
     * @param DateInterval $leeway what is allowed of the clock of the client, both ways
     */
    public function __construct(
        private DpopProofReplayGuardInterface $replays,
        private DpopNonceInterface $nonces,
        private DateInterval $maximumAge,
        private DateInterval $leeway,
    ) {
    }

    /**
     * @param string $method the method of the request that carried the proof
     * @param string $url the URL this provider publishes for the endpoint that received it
     * @param string|null $accessToken the access token the request presented, null when it presented none
     *
     * @throws InvalidDpopProofException
     * @throws UseDpopNonceException when this provider asks the client to make the proof again
     */
    public function validate(
        DpopProof $proof,
        KeyConfirmation $key,
        string $method,
        string $url,
        #[SensitiveParameter]
        ?string $accessToken,
        DateTimeImmutable $now,
    ): void {
        if (($proof->jwt->protectedHeader['typ'] ?? null) !== DpopProof::TYPE) {
            throw new InvalidDpopProofException(sprintf('A DPoP proof is a JWT of type %s, and this one is not (RFC 9449 section 4.2).', DpopProof::TYPE));
        }
        if ($proof->method() !== $method) {
            throw new InvalidDpopProofException('The htm of the DPoP proof is not the method of this request (RFC 9449 section 4.3).');
        }
        if (self::withoutQuery($proof->url()) !== $url) {
            throw new InvalidDpopProofException('The htu of the DPoP proof is not the endpoint this provider publishes for this request (RFC 9449 section 4.3).');
        }
        $this->nonces->verify($proof->nonce(), $now);
        $issuedAt = $proof->issuedAt();
        if ($issuedAt > $now->add($this->leeway)) {
            throw new InvalidDpopProofException('The DPoP proof was made later than the request that carries it (RFC 9449 section 4.3).');
        }
        $expiresAt = $issuedAt->add($this->maximumAge)->add($this->leeway);
        if ($expiresAt <= $now) {
            throw new InvalidDpopProofException('The DPoP proof is older than this provider accepts (RFC 9449 section 4.3).');
        }
        self::assertAccessTokenHash($proof, $accessToken);
        if (! $this->replays->remember($key, $proof->identifier(), $expiresAt)) {
            throw new InvalidDpopProofException('The DPoP proof was presented before (RFC 9449 section 11.1).');
        }
    }

    /**
     * RFC 9449 §4.3 and §7.1: a proof made for a request that presents an access token names that token,
     * and a proof made for a request that presents none names none. A proof carrying an "ath" where no
     * token is presented was made for another request.
     *
     * @throws InvalidDpopProofException
     */
    private static function assertAccessTokenHash(DpopProof $proof, #[SensitiveParameter] ?string $accessToken): void
    {
        $hash = $proof->accessTokenHash();
        if ($accessToken === null) {
            if ($hash !== null) {
                throw new InvalidDpopProofException('The DPoP proof names an access token this request does not present (RFC 9449 section 4.2).');
            }

            return;
        }
        if ($hash === null) {
            throw new InvalidDpopProofException('A DPoP proof presented with an access token names it in its ath (RFC 9449 section 7.1).');
        }
        if (! hash_equals(Base64Url::encode(hash('sha256', $accessToken, true)), $hash)) {
            throw new InvalidDpopProofException('The ath of the DPoP proof is not the access token this request presents (RFC 9449 section 7.1).');
        }
    }

    /**
     * RFC 9449 §4.3: the query and the fragment are no part of what a proof names, an endpoint being one
     * whatever a client appends to it.
     */
    private static function withoutQuery(string $url): string
    {
        $withoutFragment = strstr($url, '#', true);
        $url = $withoutFragment === false ? $url : $withoutFragment;
        $withoutQuery = strstr($url, '?', true);

        return $withoutQuery === false ? $url : $withoutQuery;
    }
}

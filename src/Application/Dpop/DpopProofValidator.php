<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Dpop;

use DateInterval;
use DateTimeImmutable;
use function hash;
use function hash_equals;
use Beffroi\Oidc\Domain\Dpop\DpopProof;
use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Exception\InvalidDpopProofException;
use Beffroi\Oidc\Exception\UseDpopNonceException;
use Beffroi\Oidc\Port\DpopNonceInterface;
use Beffroi\Oidc\Port\DpopProofReplayGuardInterface;
use SensitiveParameter;
use function sprintf;
use function str_ends_with;
use function strlen;
use function strpos;
use function strstr;
use function strtolower;
use function substr;

/**
 * RFC 9449 §4.3
 */
final readonly class DpopProofValidator
{
    /**
     * RFC 3986 §6.2.3
     *
     * @var array<string, string>
     */
    private const array DEFAULT_PORTS = [
        'https' => '443',
        'http' => '80',
    ];

    public function __construct(
        private DpopProofReplayGuardInterface $replays,
        private DpopNonceInterface $nonces,
        private DateInterval $maximumAge,
        private DateInterval $leeway,
    ) {
    }

    /**
     * @param string $url the URL this provider publishes for the endpoint that received it
     *
     * @throws InvalidDpopProofException
     * @throws UseDpopNonceException
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
        if (self::comparable($proof->url()) !== self::comparable($url)) {
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
     * RFC 9449 §4.3, §7.1
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
     * RFC 9449 §4.3, RFC 3986 §6.2.2, §6.2.3
     *
     * The path keeps its case: RFC 3986 §6.2.2.1 makes it case sensitive.
     */
    private static function comparable(string $url): string
    {
        $withoutFragment = strstr($url, '#', true);
        $url = $withoutFragment === false ? $url : $withoutFragment;
        $withoutQuery = strstr($url, '?', true);
        $url = $withoutQuery === false ? $url : $withoutQuery;
        $separator = strpos($url, '://');
        if ($separator === false) {
            return $url;
        }
        $scheme = strtolower(substr($url, 0, $separator));
        $rest = substr($url, $separator + 3);
        $slash = strpos($rest, '/');
        $authority = $slash === false ? $rest : substr($rest, 0, $slash);
        $path = $slash === false ? '' : substr($rest, $slash);
        $authority = strtolower($authority);
        $default = self::DEFAULT_PORTS[$scheme] ?? null;
        if ($default !== null && str_ends_with($authority, ':' . $default)) {
            $authority = substr($authority, 0, -strlen(':' . $default));
        }

        return $scheme . '://' . $authority . $path;
    }
}

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Dpop;

use DateTimeImmutable;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Oidc\Application\Key\AlgorithmNames;
use Heidi\Oidc\Domain\Dpop\DpopProof;
use Heidi\Oidc\Domain\Token\KeyConfirmation;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\InvalidDpopProofException;
use Heidi\Oidc\Exception\InvalidJwtException;
use Heidi\Oidc\Exception\UseDpopNonceException;
use Heidi\Oidc\Port\CompactJwtReaderInterface;
use Heidi\Oidc\Port\ProofKeyVerifierInterface;
use SensitiveParameter;

/**
 * The proof of possession a request carries (RFC 9449 §4): read with the reader every JWT a client sends
 * is read with, verified against the public key of its own header, and then judged by the validator.
 *
 * What comes back is the key, named by its thumbprint (RFC 7638 §3), which is the one thing the rest of
 * the provider needs: it is what a token is bound to at the endpoints that issue one, and what a
 * resource compares with the binding of the token it was handed. A request that carries no proof
 * proves no key, which is not a refusal: nothing of this is asked of a client that does not bind its
 * tokens.
 *
 * The algorithms are the ones the provider is wired with, the same ones it signs with and announces in
 * "dpop_signing_alg_values_supported", never a list kept beside them.
 */
final readonly class DpopProofVerifier
{
    public function __construct(
        private CompactJwtReaderInterface $jwts,
        private ProofKeyVerifierInterface $keys,
        private DpopProofValidator $validator,
        private SignatureAlgorithmsInterface $algorithms,
    ) {
    }

    /**
     * @param string|null $proof the DPoP header of the request, null when it carries none
     * @param string $method the method of the request
     * @param string $url the URL this provider publishes for the endpoint that received it
     * @param string|null $accessToken the access token the request presents, null when it presents none
     *
     * @throws InvalidDpopProofException
     * @throws UseDpopNonceException when this provider asks the client to make the proof again
     */
    public function verify(
        ?string $proof,
        string $method,
        string $url,
        DateTimeImmutable $now,
        #[SensitiveParameter]
        ?string $accessToken = null,
    ): ?KeyConfirmation {
        if ($proof === null || $proof === '') {
            return null;
        }
        try {
            $jwt = $this->jwts->read($proof);
        } catch (InvalidJwtException $exception) {
            throw new InvalidDpopProofException('The DPoP proof is not a readable JWT (RFC 9449 section 4.2).', $exception);
        }
        try {
            $key = new KeyConfirmation($this->keys->keyThatSigned($jwt, $this->names()));
        } catch (InvalidJwtException|InvalidArgumentException $exception) {
            throw new InvalidDpopProofException('The DPoP proof is not signed by the key it carries (RFC 9449 section 4.3).', $exception);
        }
        $this->validator->validate(new DpopProof($jwt), $key, $method, $url, $accessToken, $now);

        return $key;
    }

    /**
     * @return list<string>
     */
    private function names(): array
    {
        return AlgorithmNames::of($this->algorithms->all());
    }
}

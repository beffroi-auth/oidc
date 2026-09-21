<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\JwtLibrary;

use Heidi\Oidc\Domain\Client\ClientAssertion;
use Heidi\Oidc\Domain\Client\ClientJwks;
use Heidi\Oidc\Exception\InvalidClientAssertionException;
use Heidi\Oidc\Port\ClientAssertionKeyVerifierInterface;
use function in_array;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function sprintf;
use Throwable;

/**
 * "private_key_jwt" on web-token/jwt-library (OIDC Core §9). The key is looked for among the keys the
 * client publishes and nowhere else: a "kid" in the header names one of them, a header without one is
 * tried against all of them, and "jwk", "jku" and "x5c" are ignored (RFC 8725 §3.10). A key that names
 * another algorithm than the signature, or another use than signing, is not tried (RFC 7517 §4.2, §4.4).
 */
final readonly class JwtLibraryClientAssertionKeyVerifier implements ClientAssertionKeyVerifierInterface
{
    private JWSVerifier $verifier;

    private CompactSerializer $serializer;

    /**
     * @param AlgorithmManager $algorithms the algorithms the provider is wired with, the same list the
     *                                     methods announce in "token_endpoint_auth_signing_alg_values_supported"
     */
    public function __construct(AlgorithmManager $algorithms)
    {
        $this->verifier = new JWSVerifier($algorithms);
        $this->serializer = new CompactSerializer();
    }

    public function verify(ClientAssertion $assertion, ClientJwks $keys, array $algorithms): void
    {
        $alg = $assertion->algorithm();
        if ($alg === null || ! in_array($alg, $algorithms, true)) {
            throw new InvalidClientAssertionException(sprintf('The client assertion is signed with "%s", which this provider does not take.', $alg ?? '?'));
        }
        $keyId = $assertion->keyId();
        $candidates = $keyId === null ? $keys->keys : [$keys->find($keyId)];
        try {
            $jws = $this->serializer->unserialize($assertion->compact);
        } catch (Throwable $exception) {
            throw new InvalidClientAssertionException('The client assertion is not a compact JWS.', 0, $exception);
        }
        foreach ($candidates as $candidate) {
            if ($candidate === null || ($candidate['alg'] ?? $alg) !== $alg || ($candidate['use'] ?? 'sig') !== 'sig') {
                continue;
            }
            if ($this->verifier->verifyWithKey($jws, new JWK($candidate), 0)) {
                return;
            }
        }

        throw new InvalidClientAssertionException('The signature of the client assertion verifies against no key the client publishes.');
    }
}

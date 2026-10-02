<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\JwtLibrary;

use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidJwtException;
use Beffroi\Oidc\Port\JwtKeyVerifierInterface;
use function in_array;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function sprintf;
use Throwable;

/**
 * The signature of a JWT a client signed, on web-token/jwt-library: the assertion of "private_key_jwt"
 * (OIDC Core §9) and the request object of RFC 9101 §6.2. The key is looked for among the keys the
 * client publishes and nowhere else: a "kid" in the header names one of them, a header without one is
 * tried against all of them, and "jwk", "jku" and "x5c" are ignored (RFC 8725 §3.10). A key that names
 * another algorithm than the signature, or another use than signing, is not tried (RFC 7517 §4.2, §4.4).
 */
final readonly class JwtLibraryJwtKeyVerifier implements JwtKeyVerifierInterface
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

    public function verify(UnverifiedJwt $jwt, ClientJwks $keys, array $algorithms): void
    {
        $alg = $jwt->algorithm();
        if ($alg === null || ! in_array($alg, $algorithms, true)) {
            throw new InvalidJwtException(sprintf('The token is signed with "%s", which this provider does not take.', $alg ?? '?'));
        }
        $keyId = $jwt->keyId();
        $candidates = $keyId === null ? $keys->keys : [$keys->find($keyId)];
        try {
            $jws = $this->serializer->unserialize($jwt->compact);
        } catch (Throwable $exception) {
            throw new InvalidJwtException('The token is not a compact JWS.', 0, $exception);
        }
        foreach ($candidates as $candidate) {
            if ($candidate === null || ($candidate['alg'] ?? $alg) !== $alg || ($candidate['use'] ?? 'sig') !== 'sig') {
                continue;
            }
            if ($this->verifier->verifyWithKey($jws, new JWK($candidate), 0)) {
                return;
            }
        }

        throw new InvalidJwtException('The signature verifies against no key the client publishes.');
    }
}

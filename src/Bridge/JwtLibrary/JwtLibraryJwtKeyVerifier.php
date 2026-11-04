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
 * Only the keys the client publishes are tried; "jwk", "jku" and "x5c" are ignored (RFC 8725 §3.10).
 */
final readonly class JwtLibraryJwtKeyVerifier implements JwtKeyVerifierInterface
{
    private JWSVerifier $verifier;

    private CompactSerializer $serializer;

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

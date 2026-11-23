<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\JwtLibrary;

use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidJwtException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Throwable;

/**
 * RFC 7515 §5.2
 *
 * Whatever jwt-library throws on a token or on a key the sender chose is a refusal of the token.
 */
final readonly class JwtLibrarySignature
{
    private JWSVerifier $verifier;

    private CompactSerializer $serializer;

    public function __construct(AlgorithmManager $algorithms)
    {
        $this->verifier = new JWSVerifier($algorithms);
        $this->serializer = new CompactSerializer();
    }

    /**
     * @param array<string, mixed> $key a JWK
     *
     * @throws InvalidJwtException when the token or the key is not one jwt-library reads
     */
    public function holdsUnder(UnverifiedJwt $jwt, array $key): bool
    {
        try {
            return $this->verifier->verifyWithKey($this->serializer->unserialize($jwt->compact), new JWK($key), 0);
        } catch (Throwable $exception) {
            throw new InvalidJwtException('The signature of the token cannot be checked under the key.', 0, $exception);
        }
    }
}

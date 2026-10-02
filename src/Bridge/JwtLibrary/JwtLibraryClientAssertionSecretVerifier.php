<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\JwtLibrary;

use function base64_encode;
use Beffroi\Oidc\Domain\Client\SharedClientSecret;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidJwtException;
use Beffroi\Oidc\Port\ClientAssertionSecretVerifierInterface;
use function in_array;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function rtrim;
use function sprintf;
use function strtr;
use Throwable;

/**
 * "client_secret_jwt" on web-token/jwt-library (OIDC Core §9): the registered secret read as the octets
 * of a symmetric key (RFC 7518 §6.4), and the MAC of the assertion verified against it.
 */
final readonly class JwtLibraryClientAssertionSecretVerifier implements ClientAssertionSecretVerifierInterface
{
    private JWSVerifier $verifier;

    private CompactSerializer $serializer;

    /**
     * @param AlgorithmManager $algorithms the MAC algorithms of the methods that sign with a secret
     */
    public function __construct(AlgorithmManager $algorithms)
    {
        $this->verifier = new JWSVerifier($algorithms);
        $this->serializer = new CompactSerializer();
    }

    public function verify(UnverifiedJwt $assertion, SharedClientSecret $secret, array $algorithms): void
    {
        $alg = $assertion->algorithm();
        if ($alg === null || ! in_array($alg, $algorithms, true)) {
            throw new InvalidJwtException(sprintf('The client assertion is signed with "%s", which this method does not take.', $alg ?? '?'));
        }
        try {
            $jws = $this->serializer->unserialize($assertion->compact);
        } catch (Throwable $exception) {
            throw new InvalidJwtException('The client assertion is not a compact JWS.', 0, $exception);
        }
        $key = new JWK([
            'kty' => 'oct',
            'k' => rtrim(strtr(base64_encode($secret->value), '+/', '-_'), '='),
        ]);
        if (! $this->verifier->verifyWithKey($jws, $key, 0)) {
            throw new InvalidJwtException('The MAC of the client assertion does not verify against the secret of the client.');
        }
    }
}

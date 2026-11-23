<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\JwtLibrary;

use function array_key_exists;
use Beffroi\Oidc\Domain\Dpop\DpopProof;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidJwtException;
use Beffroi\Oidc\Port\ProofKeyVerifierInterface;
use function in_array;
use function is_array;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use function sprintf;

/**
 * RFC 9449 §4.2
 *
 * A key with private material is refused rather than stripped, and a symmetric one is refused even though no
 * wired algorithm is a MAC: a shared secret proves possession to whoever shares it (RFC 8725 §3.1).
 */
final readonly class JwtLibraryProofKeyVerifier implements ProofKeyVerifierInterface
{
    /**
     * RFC 7518 §6
     */
    private const array PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'];

    private JwtLibrarySignature $signature;

    public function __construct(AlgorithmManager $algorithms)
    {
        $this->signature = new JwtLibrarySignature($algorithms);
    }

    public function keyThatSigned(UnverifiedJwt $jwt, array $algorithms): string
    {
        $alg = $jwt->algorithm();
        if ($alg === null || ! in_array($alg, $algorithms, true)) {
            throw new InvalidJwtException(sprintf('The proof is signed with "%s", which this provider does not take.', $alg ?? '?'));
        }
        $key = self::publicKey($jwt);
        if (! $this->signature->holdsUnder($jwt, $key)) {
            throw new InvalidJwtException('The signature of the proof does not verify against the key the proof carries.');
        }

        return new JWK($key)->thumbprint('sha256');
    }

    /**
     * @throws InvalidJwtException
     *
     * @return array<string, mixed>
     */
    private static function publicKey(UnverifiedJwt $jwt): array
    {
        $values = $jwt->protectedHeader[DpopProof::KEY] ?? null;
        if (! is_array($values) || $values === []) {
            throw new InvalidJwtException('The proof carries no public key in its header (RFC 9449 section 4.2).');
        }
        foreach (self::PRIVATE_MEMBERS as $member) {
            if (array_key_exists($member, $values)) {
                throw new InvalidJwtException('The key the proof carries is not a public key (RFC 9449 section 4.3).');
            }
        }

        /** @var array<string, mixed> $values */
        return $values;
    }
}

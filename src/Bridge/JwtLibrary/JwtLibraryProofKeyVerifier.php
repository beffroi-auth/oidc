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
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function sprintf;
use Throwable;

/**
 * The signature of a DPoP proof on web-token/jwt-library: the key is the one the header of the proof
 * carries and no other (RFC 9449 §4.2), which is the whole difference with a token a client signs with
 * a key it published. "kid", "jku" and "x5c" are ignored; nothing is looked up anywhere.
 *
 * A key with private material is refused rather than stripped: a client that sent its private key sent
 * it, and a provider that quietly used the public half of it would let that pass unsaid. A symmetric
 * key is refused by the algorithms the provider is wired with, none of which is a MAC, and by the
 * refusal below, because a shared secret proves possession to whoever shares it (RFC 8725 §3.1).
 */
final readonly class JwtLibraryProofKeyVerifier implements ProofKeyVerifierInterface
{
    /**
     * RFC 7518 §6: what a key of a pair keeps to itself, and the one member of a symmetric key.
     */
    private const array PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'];

    private JWSVerifier $verifier;

    private CompactSerializer $serializer;

    /**
     * @param AlgorithmManager $algorithms the algorithms the provider is wired with
     */
    public function __construct(AlgorithmManager $algorithms)
    {
        $this->verifier = new JWSVerifier($algorithms);
        $this->serializer = new CompactSerializer();
    }

    public function keyThatSigned(UnverifiedJwt $jwt, array $algorithms): string
    {
        $alg = $jwt->algorithm();
        if ($alg === null || ! in_array($alg, $algorithms, true)) {
            throw new InvalidJwtException(sprintf('The proof is signed with "%s", which this provider does not take.', $alg ?? '?'));
        }
        $key = new JWK(self::publicKey($jwt));
        try {
            $jws = $this->serializer->unserialize($jwt->compact);
        } catch (Throwable $exception) {
            throw new InvalidJwtException('The proof is not a compact JWS.', 0, $exception);
        }
        if (! $this->verifier->verifyWithKey($jws, $key, 0)) {
            throw new InvalidJwtException('The signature of the proof does not verify against the key the proof carries.');
        }

        return $key->thumbprint('sha256');
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

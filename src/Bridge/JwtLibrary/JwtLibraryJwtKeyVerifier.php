<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\JwtLibrary;

use function array_filter;
use function array_values;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidJwtException;
use Beffroi\Oidc\Port\JwtKeyVerifierInterface;
use function count;
use function in_array;
use Jose\Component\Core\AlgorithmManager;
use function sprintf;

/**
 * Only the keys the client publishes are tried; "jwk", "jku" and "x5c" are ignored (RFC 8725 §3.10). A token that names
 * no "kid" is tried under the one key of the client that could have signed it, and refused when there are several
 * (OIDC Core §10.1): each try costs a verification the sender of the token pays nothing for.
 */
final readonly class JwtLibraryJwtKeyVerifier implements JwtKeyVerifierInterface
{
    private JwtLibrarySignature $signature;

    public function __construct(
        private AlgorithmManager $algorithms,
    ) {
        $this->signature = new JwtLibrarySignature($algorithms);
    }

    public function verify(UnverifiedJwt $jwt, ClientJwks $keys, array $algorithms): void
    {
        $alg = $jwt->algorithm();
        if ($alg === null || ! in_array($alg, $algorithms, true)) {
            throw new InvalidJwtException(sprintf('The token is signed with "%s", which this provider does not take.', $alg ?? '?'));
        }
        $keyId = $jwt->keyId();
        $named = $keyId === null ? $keys->keys : array_filter([$keys->find($keyId)], static fn (?array $key): bool => $key !== null);
        $candidates = array_values(array_filter($named, fn (array $key): bool => $this->couldHaveSigned($key, $alg)));
        if ($keyId === null && count($candidates) > 1) {
            throw new InvalidJwtException('The token names no "kid", and the client publishes several keys that could have signed it (OIDC Core section 10.1).');
        }
        foreach ($candidates as $candidate) {
            if ($this->signature->holdsUnder($jwt, $candidate)) {
                return;
            }
        }

        throw new InvalidJwtException('The signature verifies against no key the client publishes.');
    }

    /**
     * @param array<string, mixed> $key
     */
    private function couldHaveSigned(array $key, string $alg): bool
    {
        if (($key['alg'] ?? $alg) !== $alg || ($key['use'] ?? 'sig') !== 'sig' || ! $this->algorithms->has($alg)) {
            return false;
        }

        return in_array($key['kty'] ?? null, $this->algorithms->get($alg)->allowedKeyTypes(), true);
    }
}

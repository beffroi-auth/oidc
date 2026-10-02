<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidJwtException;

/**
 * Verifies the signature of a JWT a client signed against the keys it published: the assertion of
 * "private_key_jwt" (OIDC Core §9) and the request object of RFC 9101 §6.2 alike. The key is chosen by
 * the "kid" of the header among those keys alone, and by nothing the token carries otherwise: "jwk",
 * "jku" and "x5c" are ignored (RFC 8725 §3.10).
 */
interface JwtKeyVerifierInterface
{
    /**
     * @param non-empty-list<non-empty-string> $algorithms the "alg" the signature may carry
     *
     * @throws InvalidJwtException when the algorithm is not one of those, the key is not published, or
     *                             the signature does not verify
     */
    public function verify(UnverifiedJwt $jwt, ClientJwks $keys, array $algorithms): void;
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidJwtException;

/**
 * The key is chosen by the "kid" among the published keys and by nothing else: "jwk", "jku" and "x5c" are ignored
 * (RFC 8725 §3.10).
 */
interface JwtKeyVerifierInterface
{
    /**
     * @param non-empty-list<non-empty-string> $algorithms
     *
     * @throws InvalidJwtException
     */
    public function verify(UnverifiedJwt $jwt, ClientJwks $keys, array $algorithms): void;
}

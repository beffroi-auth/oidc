<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

/**
 * One shape the access tokens of this provider are written in (architecture §4.6): a JWT of RFC 9068
 * verified offline, an opaque reference presented to the introspection endpoint (RFC 7662), or whatever
 * else a deployment wires. The registration of the client chooses, nothing global.
 *
 * A shape the provider gains is a class on each side, an issuer that writes it and a verifier that
 * reads it back, both answering to the name written here and wired into the provider; what a client may
 * register and what a signing key waits for read that one wired list, never an enumeration kept beside
 * it.
 */
interface AccessTokenShapeInterface
{
    /**
     * The name a client registers in "access_token_format", and the name the issuer and the verifier of
     * this shape both answer to.
     *
     * @return non-empty-string
     */
    public function name(): string;
}

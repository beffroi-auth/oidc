<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\Null;

use DateTimeImmutable;
use Heidi\Oidc\Port\DpopNonceInterface;

/**
 * A provider that asks no nonce of a proof (RFC 9449 §8, which leaves it to the server): the window of
 * the "iat" and the "jti" already seen are what bound a proof, and a client has nothing to keep between
 * two requests. It is what a deployment gets until it wires a nonce of its own.
 */
final readonly class NoDpopNonce implements DpopNonceInterface
{
    public function verify(?string $nonce, DateTimeImmutable $now): void
    {
    }
}

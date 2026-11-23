<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Token\RefreshToken;
use DateTimeImmutable;

/**
 * RFC 9700 §4.14.2
 */
interface RefreshTokenRotationInterface
{
    /**
     * Marks the token rotated in the store, atomically, only if it is neither rotated nor revoked there; the caller's
     * copy is marked rotated with it.
     *
     * @return bool false when another request rotated or revoked it first
     */
    public function rotate(RefreshToken $token, DateTimeImmutable $now): bool;
}

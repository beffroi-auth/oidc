<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\Null;

use DateTimeImmutable;
use Beffroi\Oidc\Port\DpopNonceInterface;

/**
 * RFC 9449 §8
 */
final readonly class NoDpopNonce implements DpopNonceInterface
{
    public function verify(?string $nonce, DateTimeImmutable $now): void
    {
    }
}

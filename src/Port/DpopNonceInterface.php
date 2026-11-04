<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Oidc\Exception\UseDpopNonceException;

/**
 * RFC 9449 §8
 */
interface DpopNonceInterface
{
    /**
     * @throws UseDpopNonceException
     */
    public function verify(?string $nonce, DateTimeImmutable $now): void;
}

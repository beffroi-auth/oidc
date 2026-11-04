<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Client\Client;

/**
 * RFC 7523 §3, §4
 *
 * Shared by the workers of a deployment: an assertion replayed on another worker is a replay all the same.
 */
interface ClientAssertionReplayGuardInterface
{
    /**
     * @return bool false when the identifier was already remembered
     */
    public function remember(Client $client, string $jti, DateTimeImmutable $expiresAt): bool;
}

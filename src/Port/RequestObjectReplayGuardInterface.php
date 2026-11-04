<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Client\Client;

/**
 * CIBA Core §7.1.1
 *
 * Shared by the workers of a deployment: an object replayed on another worker is a replay all the same.
 */
interface RequestObjectReplayGuardInterface
{
    /**
     * @return bool false when the identifier was already remembered
     */
    public function remember(Client $client, string $jti, DateTimeImmutable $expiresAt): bool;
}

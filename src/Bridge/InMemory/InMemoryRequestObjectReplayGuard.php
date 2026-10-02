<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Port\RequestObjectReplayGuardInterface;
use function sprintf;

/**
 * The "jti" already seen, kept for the life of the process. What a single-process integration and the
 * tests use; a deployment of several workers points the port at a store they share, or one worker would
 * take an object another one already took.
 */
final class InMemoryRequestObjectReplayGuard implements RequestObjectReplayGuardInterface
{
    /**
     * @var array<string, DateTimeImmutable>
     */
    private array $seen = [];

    public function remember(Client $client, string $jti, DateTimeImmutable $expiresAt): bool
    {
        $key = sprintf('%s|%s|%s', $client->tenant->id->toRfc4122(), $client->registration->clientId, $jti);
        if (isset($this->seen[$key])) {
            return false;
        }
        $this->seen[$key] = $expiresAt;

        return true;
    }
}

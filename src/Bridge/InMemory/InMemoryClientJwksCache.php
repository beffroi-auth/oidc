<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\InMemory;

use Heidi\Oidc\Domain\Client\CachedClientJwks;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Port\ClientJwksCacheInterface;
use function sprintf;

/**
 * The keys of the clients kept for the life of the process. What a single-process integration and the
 * tests use; a deployment of several workers points the port at a store they share.
 */
final class InMemoryClientJwksCache implements ClientJwksCacheInterface
{
    /**
     * @var array<string, CachedClientJwks>
     */
    private array $keys = [];

    public function read(Client $client): ?CachedClientJwks
    {
        return $this->keys[self::key($client)] ?? null;
    }

    public function write(Client $client, CachedClientJwks $keys): void
    {
        $this->keys[self::key($client)] = $keys;
    }

    private static function key(Client $client): string
    {
        return sprintf('%s|%s', $client->tenant->id->toRfc4122(), $client->clientId);
    }
}

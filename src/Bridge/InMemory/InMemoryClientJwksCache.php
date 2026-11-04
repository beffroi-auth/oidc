<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use Beffroi\Oidc\Domain\Client\CachedClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Port\ClientJwksCacheInterface;

final class InMemoryClientJwksCache implements ClientJwksCacheInterface
{
    /**
     * @var array<string, CachedClientJwks> by the URL the set was read from
     */
    private array $keys = [];

    public function read(ClientUri $jwksUri): ?CachedClientJwks
    {
        return $this->keys[$jwksUri->value] ?? null;
    }

    public function write(ClientUri $jwksUri, CachedClientJwks $keys): void
    {
        $this->keys[$jwksUri->value] = $keys;
    }
}

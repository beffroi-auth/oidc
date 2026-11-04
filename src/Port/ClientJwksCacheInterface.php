<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\CachedClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;

/**
 * Filed under the URL it was read from, never under the client: a client that moves its keys is never verified
 * against what the URL it left answered.
 */
interface ClientJwksCacheInterface
{
    public function read(ClientUri $jwksUri): ?CachedClientJwks;

    public function write(ClientUri $jwksUri, CachedClientJwks $keys): void;
}

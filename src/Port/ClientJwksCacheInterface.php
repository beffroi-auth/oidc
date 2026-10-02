<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\CachedClientJwks;
use Beffroi\Oidc\Domain\Client\Client;

/**
 * Where the keys read back from a client's "jwks_uri" are kept between requests, with the moment they
 * were read. Shared by the workers of a deployment, so that a rotation of a client costs one fetch and
 * not one per worker.
 */
interface ClientJwksCacheInterface
{
    public function read(Client $client): ?CachedClientJwks;

    public function write(Client $client, CachedClientJwks $keys): void;
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;

/**
 * Reads back the JWK Set a client publishes (RFC 7591 §2). One GET over HTTPS, no redirect followed
 * (decision 0006), a bounded body and a timeout of its own: a client that hangs or answers a gigabyte
 * must not hold a worker, and a client that redirects names another URL than the one it registered.
 */
interface ClientJwksFetcherInterface
{
    /**
     * @throws ClientKeysUnavailableException
     */
    public function fetch(ClientUri $jwksUri): ClientJwks;
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;

/**
 * One GET over HTTPS, no redirect followed (decision 0006), a bounded body and a timeout of its own.
 */
interface ClientJwksFetcherInterface
{
    /**
     * @throws ClientKeysUnavailableException
     */
    public function fetch(ClientUri $jwksUri): ClientJwks;
}

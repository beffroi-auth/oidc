<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use LogicException;

/**
 * RFC 7592 §3
 */
interface ClientConfigurationEndpointInterface
{
    /**
     * @throws LogicException when the routes are not mounted under the issuer of the tenant
     */
    public function clientConfigurationFor(Tenant $tenant, string $clientId): string;
}

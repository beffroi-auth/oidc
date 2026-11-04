<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use LogicException;
use Beffroi\Oidc\Domain\Discovery\ProviderEndpoints;

interface EndpointLocatorInterface
{
    /**
     * @throws LogicException when the routes are not mounted under the issuer of the tenant
     */
    public function locate(Tenant $tenant): ProviderEndpoints;
}

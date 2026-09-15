<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Discovery\ProviderEndpoints;

/**
 * Where the endpoints of a tenant are served. Routing belongs to the integration: the module announces
 * what it is told and checks that what it announces is secure (ProviderEndpoints), nothing more. The
 * endpoints of a tenant normally sit under its issuer (OIDC Discovery §4, architecture §5.2), but that is
 * a deployment choice, not a rule of the protocol.
 */
interface EndpointLocatorInterface
{
    public function locate(Tenant $tenant): ProviderEndpoints;
}

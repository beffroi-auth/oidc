<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Discovery\ProviderEndpoints;

/**
 * Where the endpoints of a tenant are served; routing belongs to the integration (architecture §5.2).
 */
interface EndpointLocatorInterface
{
    public function locate(Tenant $tenant): ProviderEndpoints;
}

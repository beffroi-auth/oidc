<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use LogicException;
use Beffroi\Oidc\Domain\Discovery\ProviderEndpoints;

/**
 * Where the endpoints of a tenant are served; routing belongs to the integration (architecture §5.2).
 */
interface EndpointLocatorInterface
{
    /**
     * @throws LogicException when the routes of the provider are not mounted where the issuer of the
     *                        tenant makes clients look for them (OIDC Discovery §4.1): a document served
     *                        at the wrong place is not a document to serve
     */
    public function locate(Tenant $tenant): ProviderEndpoints;
}

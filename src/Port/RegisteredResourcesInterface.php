<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;

interface RegisteredResourcesInterface
{
    /**
     * @return list<ResourceIndicator> each named once
     */
    public function resourcesRegisteredIn(Tenant $tenant): array;
}

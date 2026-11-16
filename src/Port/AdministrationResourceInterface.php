<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;

/**
 * The identifier of the administration API of a tenant (decision 0038), the resource its tokens are addressed to
 * (RFC 8707 §2): the audience the provider reserves to the administrators of that tenant.
 */
interface AdministrationResourceInterface
{
    /**
     * @return ResourceIndicator|null null for a tenant whose deployment names no administration API
     */
    public function administrationResourceOf(Tenant $tenant): ?ResourceIndicator;
}

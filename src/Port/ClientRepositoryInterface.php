<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Client;

/**
 * Where the clients of a tenant come from (architecture §4.1).
 */
interface ClientRepositoryInterface
{
    public function findByClientId(Tenant $tenant, string $clientId): ?Client;
}

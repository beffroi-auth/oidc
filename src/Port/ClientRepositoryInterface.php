<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Client;

/**
 * Where the clients of a tenant come from (architecture §4.1).
 */
interface ClientRepositoryInterface
{
    public function findByClientId(Tenant $tenant, string $clientId): ?Client;
}

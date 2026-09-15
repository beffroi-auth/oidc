<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Client;

/**
 * Where the clients of a tenant come from: the bundle configuration in the first spike, a database and
 * dynamic registration (RFC 7591) later. The port does not change (architecture §4.1).
 */
interface ClientRepositoryInterface
{
    /**
     * @param string $clientId as the client presented it; the match is exact
     */
    public function findByClientId(Tenant $tenant, string $clientId): ?Client;
}

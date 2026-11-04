<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Client\Registration\ClientRetention;

/**
 * A source of declared clients never implements it, so that a client a deployment declared is never deleted.
 */
interface UnusedClientsInterface
{
    /**
     * @return list<ClientRecord> oldest use first
     */
    public function unusedIn(Tenant $tenant, ClientRetention $retention, int $limit): array;
}

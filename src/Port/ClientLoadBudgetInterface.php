<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\LoadBudgetSpentException;

/**
 * Counted by tenant and by authenticated client (decision 0014): a budget counted on the "client_id" of a request
 * not yet authenticated is emptied by naming somebody else's client.
 */
interface ClientLoadBudgetInterface
{
    /**
     * @throws LoadBudgetSpentException
     */
    public function consume(Tenant $tenant, string $clientId): void;
}

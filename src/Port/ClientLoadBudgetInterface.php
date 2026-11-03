<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\LoadBudgetSpentException;

/**
 * What a client may ask of the provider in a window (decision 0014): the share of the load a client
 * takes, counted where its authentication succeeded and nowhere earlier. The identifier of an
 * authenticated client is something the caller cannot choose for somebody else, which the "client_id" a
 * request carries before it is authenticated is not: a budget counted on that one is emptied by naming
 * the client of somebody else, and the limit becomes the weapon. A client that only names itself and
 * proves nothing (RFC 6749 §2.1) is bounded by the budget of its origin, which is the application's.
 *
 * It is counted by tenant and by client, because two tenants may register the same identifier and one
 * bucket would make either pay for the other. What the window is and how it is kept is the
 * implementation's; that there is one, and that no deployment removes it, is the decision's.
 */
interface ClientLoadBudgetInterface
{
    /**
     * @throws LoadBudgetSpentException when the window has no room left for this client
     */
    public function consume(Tenant $tenant, string $clientId): void;
}

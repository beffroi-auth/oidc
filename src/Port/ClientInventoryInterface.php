<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\InventoriedClient;

/**
 * What a source of clients shows of itself to whoever runs the deployment (decision 0009). It is the
 * counterpart of `ClientSourceInterface` and not a half of it: what resolves a client for a request
 * answers one identifier at a time and knows nothing of dates, and what lists them for a person answers
 * every client of a tenant and nothing a request is served against. The two callers are disjoint, so the
 * ports are.
 *
 * Every source implements it, which is what makes a list of clients the list of what is wired rather
 * than a list somebody keeps up to date.
 */
interface ClientInventoryInterface
{
    /**
     * @return iterable<InventoriedClient> the clients of that tenant this source holds, in the order it
     *                                     holds them; nothing for a tenant it holds none of
     */
    public function inventoryIn(Tenant $tenant): iterable;
}

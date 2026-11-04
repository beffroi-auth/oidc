<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\InventoriedClient;

interface ClientInventoryInterface
{
    /**
     * @return iterable<InventoriedClient>
     */
    public function inventoryIn(Tenant $tenant): iterable;
}

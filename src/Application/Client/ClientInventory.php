<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\InventoriedClient;
use Beffroi\Oidc\Port\ClientInventoryInterface;

final readonly class ClientInventory implements ClientInventoryInterface
{
    /**
     * @param iterable<ClientInventoryInterface> $sources in order of precedence
     */
    public function __construct(
        private iterable $sources,
    ) {
    }

    /**
     * @return iterable<InventoriedClient>
     */
    public function inventoryIn(Tenant $tenant): iterable
    {
        foreach ($this->sources as $source) {
            yield from $source->inventoryIn($tenant);
        }
    }

    public function find(Tenant $tenant, string $clientId): ?InventoriedClient
    {
        foreach ($this->inventoryIn($tenant) as $client) {
            if ($client->clientId === $clientId) {
                return $client;
            }
        }

        return null;
    }
}

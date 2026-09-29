<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\InventoriedClient;
use Heidi\Oidc\Port\ClientInventoryInterface;

/**
 * Every client of a tenant, whatever holds it (decision 0009): the ones a deployment declared and the
 * ones that registered themselves, in the order the sources are wired, each saying where it came from.
 *
 * It is the reading counterpart of `RegisteredClients`, which answers what the protocol derives from the
 * set of clients; this answers what a person is shown. A source wired later is in both by being wired,
 * and neither holds a list of how many there are.
 */
final readonly class ClientInventory implements ClientInventoryInterface
{
    /**
     * @param iterable<ClientInventoryInterface> $sources the sources that hold clients, in the order they are wired
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

    /**
     * The client of that tenant carrying that identifier, from the first source that holds one, which is
     * the source a request would be served from. Null when no source holds it.
     */
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

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\InventoriedClient;
use Beffroi\Oidc\Port\ClientInventoryInterface;
use Beffroi\Oidc\Port\ClientSourceInterface;

/**
 * For tests and for the examples: nothing here survives the process.
 */
final class InMemoryClientRepository implements ClientInventoryInterface, ClientSourceInterface
{
    public const string SOURCE = 'memory';

    /**
     * @var list<Client>
     */
    private array $clients = [];

    public function findByClientId(Tenant $tenant, string $clientId): ?Client
    {
        foreach ($this->clients as $client) {
            if ($client->belongsTo($tenant) && $client->registration->clientId === $clientId) {
                return $client;
            }
        }

        return null;
    }

    /**
     * What this source holds for that tenant, in the order it was given them. What the set of them means
     * is read once, where every source is read (`RegisteredClients`).
     */
    public function registrationsIn(Tenant $tenant): iterable
    {
        foreach ($this->clients as $client) {
            if ($client->belongsTo($tenant)) {
                yield $client->registration;
            }
        }
    }

    public function inventoryIn(Tenant $tenant): iterable
    {
        foreach ($this->registrationsIn($tenant) as $registration) {
            yield new InventoriedClient(self::SOURCE, $registration->clientId, $registration->presentation->name);
        }
    }

    public function save(Client $client): void
    {
        $this->clients[] = $client;
    }
}

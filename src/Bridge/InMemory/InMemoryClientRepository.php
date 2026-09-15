<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\InMemory;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Port\ClientRepositoryInterface;

/**
 * For tests and for the examples: nothing here survives the process.
 */
final class InMemoryClientRepository implements ClientRepositoryInterface
{
    /**
     * @var list<Client>
     */
    private array $clients = [];

    public function findByClientId(Tenant $tenant, string $clientId): ?Client
    {
        foreach ($this->clients as $client) {
            if ($client->belongsTo($tenant) && $client->clientId === $clientId) {
                return $client;
            }
        }

        return null;
    }

    public function save(Client $client): void
    {
        $this->clients[] = $client;
    }
}

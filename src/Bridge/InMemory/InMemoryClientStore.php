<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\InMemory;

use function array_filter;
use function array_find;
use function array_values;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\ClientRecord;
use Heidi\Oidc\Port\ClientStoreInterface;

/**
 * For tests and for the examples: nothing here survives the process. A row written twice is one row, as it
 * is in a store keyed by the identifier the provider drew.
 */
final class InMemoryClientStore implements ClientStoreInterface
{
    /**
     * @var list<ClientRecord>
     */
    public private(set) array $records = [];

    public function save(ClientRecord $record): void
    {
        $this->records = [
            ...array_values(array_filter(
                $this->records,
                static fn (ClientRecord $kept): bool => ! $kept->id->equals($record->id),
            )),
            $record,
        ];
    }

    public function findRecord(Tenant $tenant, string $clientId): ?ClientRecord
    {
        return array_find(
            $this->records,
            static fn (ClientRecord $record): bool => $record->belongsTo($tenant) && $record->clientId === $clientId,
        );
    }

    public function remove(ClientRecord $record): void
    {
        $this->records = array_values(array_filter(
            $this->records,
            static fn (ClientRecord $kept): bool => ! $kept->id->equals($record->id),
        ));
    }
}

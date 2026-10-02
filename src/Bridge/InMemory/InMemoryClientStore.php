<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use function array_filter;
use function array_find;
use function array_values;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use function array_slice;
use Beffroi\Oidc\Domain\Client\Registration\ClientRetention;
use Beffroi\Oidc\Port\ClientStoreInterface;
use Beffroi\Oidc\Port\UnusedClientsInterface;

/**
 * For tests and for the examples: nothing here survives the process. A row written twice is one row, as it
 * is in a store keyed by the identifier the provider drew.
 */
final class InMemoryClientStore implements ClientStoreInterface, UnusedClientsInterface
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

    public function unusedIn(Tenant $tenant, ClientRetention $retention, int $limit): array
    {
        $unused = array_values(array_filter(
            $this->records,
            static fn (ClientRecord $record): bool => (
                $record->belongsTo($tenant)
                && (
                    $record->lastUsedAt === null
                        ? $record->issuedAt < $retention->registeredSince
                        : $record->lastUsedAt < $retention->usedSince
                )
            ),
        ));

        return $limit < 1 ? [] : array_slice($unused, 0, $limit);
    }

    public function remove(ClientRecord $record): void
    {
        $this->records = array_values(array_filter(
            $this->records,
            static fn (ClientRecord $kept): bool => ! $kept->id->equals($record->id),
        ));
    }
}

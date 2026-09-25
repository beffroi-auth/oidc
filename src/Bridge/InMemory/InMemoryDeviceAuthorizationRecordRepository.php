<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\InMemory;

use function array_find;
use DateTimeImmutable;
use Heidi\Oidc\Domain\Device\DeviceAuthorizationRecord;
use Heidi\Oidc\Port\DeviceAuthorizationRecordRepositoryInterface;

/**
 * For tests and for the examples: nothing here survives the process, and one process claims a record once
 * because nothing else runs beside it.
 */
final class InMemoryDeviceAuthorizationRecordRepository implements DeviceAuthorizationRecordRepositoryInterface
{
    /**
     * @var array<string, DeviceAuthorizationRecord> by device code hash
     */
    private array $records = [];

    public function findByDeviceCodeHash(string $deviceCodeHash): ?DeviceAuthorizationRecord
    {
        return $this->records[$deviceCodeHash] ?? null;
    }

    public function findByUserCodeHash(string $userCodeHash): ?DeviceAuthorizationRecord
    {
        return array_find(
            $this->records,
            static fn (DeviceAuthorizationRecord $record): bool => $record->userCodeHash === $userCodeHash,
        );
    }

    public function consume(DeviceAuthorizationRecord $record, DateTimeImmutable $now): bool
    {
        $stored = $this->records[$record->deviceCodeHash] ?? null;
        if ($stored === null || $stored->isUsed()) {
            return false;
        }
        $stored->consume($now);

        return true;
    }

    public function save(DeviceAuthorizationRecord $record): void
    {
        $this->records[$record->deviceCodeHash] = $record;
    }
}

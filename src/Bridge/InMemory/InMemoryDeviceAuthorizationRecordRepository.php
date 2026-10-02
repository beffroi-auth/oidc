<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use function array_find;
use DateTimeImmutable;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Device\DeviceAuthorizationRecord;
use Beffroi\Oidc\Port\CanRevokeGrantsByConsentInterface;
use Beffroi\Oidc\Port\DeviceAuthorizationRecordRepositoryInterface;
use Beffroi\Oidc\Port\RecordedGrantsInterface;
use Symfony\Component\Uid\Uuid;

/**
 * For tests and for the examples: nothing here survives the process, and one process claims a record once
 * because nothing else runs beside it.
 */
final class InMemoryDeviceAuthorizationRecordRepository implements
    CanRevokeGrantsByConsentInterface,
    DeviceAuthorizationRecordRepositoryInterface,
    RecordedGrantsInterface
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

    public function findByGrantId(Uuid $grantId): ?DeviceAuthorizationRecord
    {
        return array_find(
            $this->records,
            static fn (DeviceAuthorizationRecord $record): bool => $record->grantId->equals($grantId),
        );
    }

    /**
     * @return list<DeviceAuthorizationRecord>
     */
    public function revokeByConsent(Consent $consent, DateTimeImmutable $now): array
    {
        $revoked = [];
        foreach ($this->records as $record) {
            $session = $record->session;
            if ($record->isRevoked() || $session === null || ! $consent->covers($session, $record->clientId)) {
                continue;
            }
            $record->revoke($now);
            $this->save($record);
            $revoked[] = $record;
        }

        return $revoked;
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

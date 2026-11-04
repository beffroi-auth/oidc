<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Device\DeviceAuthorizationRecord;

/**
 * A spent record stays until it expires, so that its second presentation can be told from an unknown device code.
 */
interface DeviceAuthorizationRecordRepositoryInterface
{
    /**
     * @param string $deviceCodeHash the hex SHA-256 of the device code
     */
    public function findByDeviceCodeHash(string $deviceCodeHash): ?DeviceAuthorizationRecord;

    /**
     * @param string $userCodeHash see UserCode::hashOf()
     */
    public function findByUserCodeHash(string $userCodeHash): ?DeviceAuthorizationRecord;

    /**
     * Atomic: of concurrent requests presenting the same device code, exactly one is told true, and a caller told false
     * holds a record whose state is the winner's (RFC 8628 §3.5).
     */
    public function consume(DeviceAuthorizationRecord $record, DateTimeImmutable $now): bool;

    public function save(DeviceAuthorizationRecord $record): void;
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Device\DeviceAuthorizationRecord;

/**
 * Where the record of a device authorization request waits for its user and for the client that polls for
 * it (RFC 8628 §3.2, §3.4). A spent record stays until it expires, so that its second presentation can be
 * told from a device code nobody ever issued; what is past its lifetime grants nothing whether the store
 * still holds it or not.
 */
interface DeviceAuthorizationRecordRepositoryInterface
{
    /**
     * @param string $deviceCodeHash the hex SHA-256 of the device code the client polls with
     */
    public function findByDeviceCodeHash(string $deviceCodeHash): ?DeviceAuthorizationRecord;

    /**
     * What the page the user types on looks a code up by.
     *
     * @param string $userCodeHash see UserCode::hashOf()
     */
    public function findByUserCodeHash(string $userCodeHash): ?DeviceAuthorizationRecord;

    /**
     * Atomic: of any number of requests presenting the same device code at once, exactly one is told true
     * (RFC 8628 §3.5, a device code being spent once). A caller told false holds a record whose state is
     * the winner's.
     */
    public function consume(DeviceAuthorizationRecord $record, DateTimeImmutable $now): bool;

    public function save(DeviceAuthorizationRecord $record): void;
}

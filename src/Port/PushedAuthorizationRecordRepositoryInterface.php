<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRecord;

/**
 * A used record stays until it expires, so that its second presentation can be told from an unknown reference.
 */
interface PushedAuthorizationRecordRepositoryInterface
{
    /**
     * @param string $requestUriHash see RequestUri::hashOf()
     */
    public function findByRequestUriHash(string $requestUriHash): ?PushedAuthorizationRecord;

    /**
     * Atomic: of concurrent requests presenting the same reference, exactly one is told true, and a caller told false
     * holds a record whose state is the winner's (RFC 9126 §4).
     */
    public function consume(PushedAuthorizationRecord $record, DateTimeImmutable $now): bool;

    public function save(PushedAuthorizationRecord $record): void;
}

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use DateTimeImmutable;
use Heidi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRecord;

/**
 * Where the record of a pushed authorization request waits for the authorization endpoint (RFC 9126
 * §2.2, §4). A used record stays until it expires, so that its second presentation can be told from a
 * reference nobody ever issued; what is past its lifetime grants nothing whether the store still holds
 * it or not.
 */
interface PushedAuthorizationRecordRepositoryInterface
{
    /**
     * @param string $requestUriHash see RequestUri::hashOf()
     */
    public function findByRequestUriHash(string $requestUriHash): ?PushedAuthorizationRecord;

    /**
     * Atomic: of any number of requests presenting the same reference at once, exactly one is told true
     * (RFC 9126 §4). A caller told false holds a record whose state is the winner's.
     */
    public function consume(PushedAuthorizationRecord $record, DateTimeImmutable $now): bool;

    public function save(PushedAuthorizationRecord $record): void;
}

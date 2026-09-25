<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\InMemory;

use DateTimeImmutable;
use Heidi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRecord;
use Heidi\Oidc\Port\PushedAuthorizationRecordRepositoryInterface;

/**
 * For tests and for the examples: nothing here survives the process, and one process claims a record
 * once because nothing else runs beside it.
 */
final class InMemoryPushedAuthorizationRecordRepository implements PushedAuthorizationRecordRepositoryInterface
{
    /**
     * @var array<string, PushedAuthorizationRecord> by request URI hash
     */
    private array $records = [];

    public function findByRequestUriHash(string $requestUriHash): ?PushedAuthorizationRecord
    {
        return $this->records[$requestUriHash] ?? null;
    }

    public function consume(PushedAuthorizationRecord $record, DateTimeImmutable $now): bool
    {
        $stored = $this->records[$record->requestUriHash] ?? null;
        if ($stored === null || $stored->isUsed()) {
            return false;
        }
        $stored->consume($now);

        return true;
    }

    public function save(PushedAuthorizationRecord $record): void
    {
        $this->records[$record->requestUriHash] = $record;
    }
}

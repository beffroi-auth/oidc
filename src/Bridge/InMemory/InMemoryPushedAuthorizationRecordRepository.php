<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRecord;
use Beffroi\Oidc\Port\PushedAuthorizationRecordRepositoryInterface;

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

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;

/**
 * A spent record stays until it expires, so that its second presentation can be told from an unknown auth_req_id.
 */
interface BackchannelAuthenticationRecordRepositoryInterface
{
    /**
     * @param string $authRequestIdHash the hex SHA-256 of the auth_req_id
     */
    public function findByAuthRequestIdHash(string $authRequestIdHash): ?BackchannelAuthenticationRecord;

    /**
     * The requests made for this user that are neither answered, spent, revoked nor expired.
     *
     * @return list<BackchannelAuthenticationRecord> oldest first
     */
    public function awaitingAnAnswerBy(User $user, DateTimeImmutable $now): array;

    /**
     * Atomic: of concurrent requests presenting the same auth_req_id, exactly one is told true, and a caller told false
     * holds a record whose state is the winner's (CIBA Core §10.1).
     */
    public function consume(BackchannelAuthenticationRecord $record, DateTimeImmutable $now): bool;

    public function save(BackchannelAuthenticationRecord $record): void;
}

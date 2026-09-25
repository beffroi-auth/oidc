<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use DateTimeImmutable;
use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;

/**
 * Where the record of a backchannel authentication request waits for its user and for the client that
 * comes back for it (CIBA Core §7, §10.1). A spent record stays until it expires, so that its second
 * presentation can be told from an auth_req_id nobody ever issued; what is past its lifetime grants
 * nothing whether the store still holds it or not.
 */
interface BackchannelAuthenticationRecordRepositoryInterface
{
    /**
     * @param string $authRequestIdHash the hex SHA-256 of the auth_req_id the client comes back with
     */
    public function findByAuthRequestIdHash(string $authRequestIdHash): ?BackchannelAuthenticationRecord;

    /**
     * What the page where a user answers reads: the requests made for that user that are still waiting
     * for an answer, oldest first. A request that expired, that was answered or that was spent is not one
     * of them.
     *
     * @return list<BackchannelAuthenticationRecord>
     */
    public function awaitingAnAnswerBy(User $user, DateTimeImmutable $now): array;

    /**
     * Atomic: of any number of requests presenting the same auth_req_id at once, exactly one is told true
     * (CIBA Core §10.1, an auth_req_id being spent once). A caller told false holds a record whose state
     * is the winner's.
     */
    public function consume(BackchannelAuthenticationRecord $record, DateTimeImmutable $now): bool;

    public function save(BackchannelAuthenticationRecord $record): void;
}

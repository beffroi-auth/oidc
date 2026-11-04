<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\User;
use function array_find;
use Beffroi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Port\BackchannelAuthenticationRecordRepositoryInterface;
use Beffroi\Oidc\Port\CanRevokeGrantsByConsentInterface;
use Beffroi\Oidc\Port\RecordedGrantsInterface;
use Symfony\Component\Uid\Uuid;
use function usort;

final class InMemoryBackchannelAuthenticationRecordRepository implements
    BackchannelAuthenticationRecordRepositoryInterface,
    CanRevokeGrantsByConsentInterface,
    RecordedGrantsInterface
{
    /**
     * @var array<string, BackchannelAuthenticationRecord> by auth_req_id hash
     */
    private array $records = [];

    public function findByAuthRequestIdHash(string $authRequestIdHash): ?BackchannelAuthenticationRecord
    {
        return $this->records[$authRequestIdHash] ?? null;
    }

    public function findByGrantId(Uuid $grantId): ?BackchannelAuthenticationRecord
    {
        return array_find(
            $this->records,
            static fn (BackchannelAuthenticationRecord $record): bool => $record->grantId->equals($grantId),
        );
    }

    /**
     * @return list<BackchannelAuthenticationRecord>
     */
    public function revokeByConsent(Consent $consent, DateTimeImmutable $now): array
    {
        $revoked = [];
        foreach ($this->records as $record) {
            $user = $record->user;
            if ($record->isRevoked() || $user === null || ! $consent->coversUser($user, $record->clientId)) {
                continue;
            }
            $record->revoke($now);
            $this->save($record);
            $revoked[] = $record;
        }

        return $revoked;
    }

    public function awaitingAnAnswerBy(User $user, DateTimeImmutable $now): array
    {
        $waiting = [];
        foreach ($this->records as $record) {
            if (! $record->mayBeAnsweredBy($user) || $record->isAnswered() || $record->isUsed() || $record->isExpired($now)) {
                continue;
            }
            $waiting[] = $record;
        }
        usort(
            $waiting,
            static fn (BackchannelAuthenticationRecord $first, BackchannelAuthenticationRecord $second): int => $first->issuedAt <=> $second->issuedAt,
        );

        return $waiting;
    }

    public function consume(BackchannelAuthenticationRecord $record, DateTimeImmutable $now): bool
    {
        $stored = $this->records[$record->authRequestIdHash] ?? null;
        if ($stored === null || $stored->isUsed()) {
            return false;
        }
        $stored->consume($now);

        return true;
    }

    public function save(BackchannelAuthenticationRecord $record): void
    {
        $this->records[$record->authRequestIdHash] = $record;
    }
}

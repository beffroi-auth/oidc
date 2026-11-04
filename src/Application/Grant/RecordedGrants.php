<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Grant;

use function array_merge;
use DateTimeImmutable;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Grant\GrantRecord;
use Beffroi\Oidc\Port\CanRevokeGrantsByConsentInterface;
use Beffroi\Oidc\Port\RecordedGrantsInterface;
use Symfony\Component\Uid\Uuid;

final readonly class RecordedGrants implements RecordedGrantsInterface, CanRevokeGrantsByConsentInterface
{
    /**
     * @param iterable<RecordedGrantsInterface> $stores
     */
    public function __construct(
        private iterable $stores,
    ) {
    }

    public function findByGrantId(Uuid $grantId): ?GrantRecord
    {
        foreach ($this->stores as $store) {
            $grant = $store->findByGrantId($grantId);
            if ($grant !== null) {
                return $grant;
            }
        }

        return null;
    }

    /**
     * @return list<GrantRecord>
     */
    public function revokeByConsent(Consent $consent, DateTimeImmutable $now): array
    {
        $revoked = [];
        foreach ($this->stores as $store) {
            if (! $store instanceof CanRevokeGrantsByConsentInterface) {
                continue;
            }
            $revoked = array_merge($revoked, $store->revokeByConsent($consent, $now));
        }

        return $revoked;
    }
}

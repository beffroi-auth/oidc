<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Grant;

use function array_merge;
use DateTimeImmutable;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Domain\Grant\GrantRecord;
use Heidi\Oidc\Port\CanRevokeGrantsByConsentInterface;
use Heidi\Oidc\Port\RecordedGrantsInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The grants of the provider, read as one (architecture §4.6): the stores wired here are the records the
 * flows write, and a reader asking what a token descends from asks them and not one of them. A flow added
 * to the provider is a store added to this wiring, so the reader never learns the name of a grant.
 *
 * The first store that keeps the record answers, a grant identifier being unique across them: the records
 * are drawn as every other secret of this provider is, and two flows cannot name the same grant.
 */
final readonly class RecordedGrants implements RecordedGrantsInterface, CanRevokeGrantsByConsentInterface
{
    /**
     * @param iterable<RecordedGrantsInterface> $stores the records that carry a grant, in the order they
     *                                                  are wired
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

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Grant\GrantRecord;

/**
 * A record still waiting for its user or for its client is revoked too: nothing may come of it now.
 */
interface CanRevokeGrantsByConsentInterface
{
    /**
     * @return list<GrantRecord> those this call revoked, oldest first
     */
    public function revokeByConsent(Consent $consent, DateTimeImmutable $now): array;
}

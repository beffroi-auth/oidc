<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Grant\GrantRecord;

/**
 * A companion of RecordedGrantsInterface: the grants a user left to a client while that consent was in
 * force, taken out of use when they take it back (architecture §4.3). Whether the grant a token descends
 * from is still alive is what says the token is (architecture §4.6), so these are what a user reaches when
 * they say the client may no longer act for them, whichever flow the client used to obtain them.
 *
 * A record still waiting for its user or for its client granted nothing yet and is revoked all the same,
 * since nothing may come of it now.
 */
interface CanRevokeGrantsByConsentInterface
{
    /**
     * @return list<GrantRecord> the grants revoked by this call, oldest first; one already revoked keeps
     *                           its date and is not one of them
     */
    public function revokeByConsent(Consent $consent, DateTimeImmutable $now): array;
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Token\StoredAccessToken;

/**
 * A companion of AccessTokenRepositoryInterface: every token a client holds for a user, for the consent
 * that user takes back (architecture §4.3). A token a client holds for itself descends from no user and
 * from no consent, and is not one of them.
 */
interface CanRevokeAccessTokensByConsentInterface
{
    /**
     * @return list<StoredAccessToken> the records removed
     */
    public function revokeByConsent(Consent $consent): array;
}

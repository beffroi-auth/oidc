<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Token\RefreshToken;

/**
 * A companion of RefreshTokenRepositoryInterface: what a client can still renew for a user, for the
 * consent that user takes back (architecture §4.3).
 */
interface RefreshTokensOfAConsentInterface
{
    /**
     * @return list<RefreshToken> whatever their state, oldest first; one of a client no longer registered
     *                            is not listed
     */
    public function ofConsent(Consent $consent): array;
}

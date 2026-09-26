<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Consent\Consent;

/**
 * A companion of AuthorizationCodeRepositoryInterface: the grants a user left to a client while that
 * consent was in force. Whether the grant a token descends from is still alive is what says the token is
 * (architecture §4.6), so these are what a user reaches when they say the client may no longer act for
 * them (architecture §4.3).
 */
interface GrantsOfAConsentInterface
{
    /**
     * @return list<AuthorizationCode> whatever their state, oldest first; one of a client no longer
     *                                 registered is not listed
     */
    public function ofConsent(Consent $consent): array;
}

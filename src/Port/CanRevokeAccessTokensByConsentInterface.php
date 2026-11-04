<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Token\StoredAccessToken;

interface CanRevokeAccessTokensByConsentInterface
{
    /**
     * @return list<StoredAccessToken>
     */
    public function revokeByConsent(Consent $consent): array;
}

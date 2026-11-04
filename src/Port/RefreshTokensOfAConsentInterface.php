<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Token\RefreshToken;

interface RefreshTokensOfAConsentInterface
{
    /**
     * @return list<RefreshToken> whatever their state, oldest first
     */
    public function ofConsent(Consent $consent): array;
}

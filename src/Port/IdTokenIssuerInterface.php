<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;

/**
 * Mints the ID token of a response (OIDC Core §2, architecture §4.6); the access token is given for "at_hash".
 */
interface IdTokenIssuerInterface
{
    /**
     * @return string the compact JWS
     */
    public function issue(GrantedAuthorization $authorization, AccessToken $accessToken, DateTimeImmutable $now): string;
}

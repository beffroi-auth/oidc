<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;

/**
 * Mints the ID token of a response (OIDC Core §2, §3.1.3.6; architecture §4.6). The access token of the
 * same response is given for "at_hash"; the nonce, the authentication and the claims requested are in
 * the authorization.
 */
interface IdTokenIssuerInterface
{
    /**
     * @return string the compact JWS
     */
    public function issue(GrantedAuthorization $authorization, AccessToken $accessToken, DateTimeImmutable $now): string;
}

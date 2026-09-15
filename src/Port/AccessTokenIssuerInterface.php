<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;

/**
 * Mints the access token of a response (architecture §4.6: a signed JWT, "typ" at+jwt, RFC 9068). The
 * grants know what was authorized; the issuer knows how the token is written and how long it lives.
 */
interface AccessTokenIssuerInterface
{
    public function issue(GrantedAuthorization $authorization, DateTimeImmutable $now): AccessToken;
}

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;

/**
 * Mints the access token of a response (architecture §4.6): how it is written and how long it lives.
 */
interface AccessTokenIssuerInterface
{
    public function issue(GrantedAuthorization $authorization, DateTimeImmutable $now): AccessToken;
}

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;

/**
 * Mints the access token of a response (architecture §4.6): how it is written and how long it lives.
 *
 * What a caller of the token endpoint sees is one issuer, which writes the token in the shape the client
 * is registered for; the issuer of one shape declares which one it writes
 * (AccessTokenShapeIssuerInterface), and ServedAccessTokenShapes is the one that picks among them.
 */
interface AccessTokenIssuerInterface
{
    public function issue(GrantedAuthorization $authorization, DateTimeImmutable $now): AccessToken;
}

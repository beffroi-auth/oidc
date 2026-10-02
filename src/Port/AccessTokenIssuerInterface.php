<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\AuthorizationInterface;

/**
 * Mints the access token of a response (architecture §4.6): how it is written and how long it lives.
 *
 * What a caller of the token endpoint sees is one issuer, which writes the token in the shape the client
 * is registered for; the issuer of one shape declares which one it writes
 * (AccessTokenShapeIssuerInterface), and ServedAccessTokenShapes is the one that picks among them.
 */
interface AccessTokenIssuerInterface
{
    public function issue(AuthorizationInterface $authorization, DateTimeImmutable $now): AccessToken;
}

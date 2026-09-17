<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use DateInterval;
use DateTimeImmutable;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Port\AccessTokenIssuerInterface;
use Heidi\Oidc\Port\AccessTokenRepositoryInterface;

/**
 * The opaque shape of the access token (architecture §4.6): a random value the client presents as it is,
 * and a record the provider keeps under its hash with everything the JWT shape would carry as claims,
 * both the repository's doing. Whoever holds the token learns nothing from it; whoever must honour it
 * asks the introspection endpoint (RFC 7662), which is also how a revocation reaches a resource server
 * before the token expires. Same lifetime as the JWT shape: a revocation is a facility, not a reason to
 * live longer.
 */
final readonly class OpaqueAccessTokenIssuer implements AccessTokenIssuerInterface
{
    public function __construct(
        private AccessTokenRepositoryInterface $tokens,
        private DateInterval $lifetime = new DateInterval('PT10M'),
    ) {
    }

    public function issue(GrantedAuthorization $authorization, DateTimeImmutable $now): AccessToken
    {
        $expiresAt = $now->add($this->lifetime);

        return new AccessToken($this->tokens->issue($authorization, $now, $expiresAt), $now, $expiresAt);
    }
}

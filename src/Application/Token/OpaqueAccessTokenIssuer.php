<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use DateInterval;
use DateTimeImmutable;
use Heidi\Oidc\Domain\Token\AccessToken;
use Heidi\Oidc\Domain\Token\AuthorizationInterface;
use Heidi\Oidc\Port\AccessTokenShapeIssuerInterface;
use Heidi\Oidc\Port\AccessTokenRepositoryInterface;

/**
 * The opaque shape of the access token (architecture §4.6): a random value, and a record kept under its
 * hash with everything the JWT shape would carry. Same lifetime as the JWT shape.
 */
final readonly class OpaqueAccessTokenIssuer implements AccessTokenShapeIssuerInterface
{
    public function __construct(
        private AccessTokenRepositoryInterface $tokens,
        private DateInterval $lifetime = new DateInterval('PT10M'),
    ) {
    }

    /**
     * The name a client registers to receive its access tokens in this shape, which
     * OpaqueAccessTokenVerifier reads them back under.
     */
    public function name(): string
    {
        return 'opaque';
    }

    public function issue(AuthorizationInterface $authorization, DateTimeImmutable $now): AccessToken
    {
        $expiresAt = $now->add($this->lifetime);

        return new AccessToken($this->tokens->issue($authorization, $now, $expiresAt), $now, $expiresAt);
    }
}

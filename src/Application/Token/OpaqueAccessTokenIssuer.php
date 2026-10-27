<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use DateInterval;
use DateTimeImmutable;
use Beffroi\Oidc\Application\Secret\SecretDrawer;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\AddressedAccessToken;
use Beffroi\Oidc\Domain\Token\AuthorizationInterface;
use Beffroi\Oidc\Port\AccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\AccessTokenShapeIssuerInterface;

/**
 * The opaque shape of the access token (architecture §4.6): a random value, and a record kept under its
 * hash with everything the JWT shape would carry. Same lifetime as the JWT shape. Nothing signs it, so
 * nothing is opened when it is addressed.
 */
final readonly class OpaqueAccessTokenIssuer implements AccessTokenShapeIssuerInterface
{
    public function __construct(
        private AccessTokenRepositoryInterface $tokens,
        private SecretDrawer $secrets,
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

    public function address(Client $client): AddressedAccessToken
    {
        return new AddressedAccessToken();
    }

    public function issue(AuthorizationInterface $authorization, AddressedAccessToken $addressed, DateTimeImmutable $now): AccessToken
    {
        $expiresAt = $now->add($this->lifetime);
        $value = $this->secrets->draw();
        $this->tokens->save($authorization->storedUnder(DrawnSecret::digestOf($value), $now, $expiresAt));

        return new AccessToken($value, $now, $expiresAt);
    }
}

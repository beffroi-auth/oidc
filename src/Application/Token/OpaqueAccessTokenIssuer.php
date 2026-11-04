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

final readonly class OpaqueAccessTokenIssuer implements AccessTokenShapeIssuerInterface
{
    public function __construct(
        private AccessTokenRepositoryInterface $tokens,
        private SecretDrawer $secrets,
        private DateInterval $lifetime = new DateInterval('PT10M'),
    ) {
    }

    public function name(): string
    {
        return 'opaque';
    }

    public function address(Client $client): AddressedAccessToken
    {
        return new AddressedAccessToken();
    }

    public function addressFor(AuthorizationInterface $authorization): AddressedAccessToken
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

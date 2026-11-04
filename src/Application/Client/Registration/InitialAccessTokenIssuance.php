<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use DateInterval;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Secret\SecretDrawer;
use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Client\Registration\IssuedInitialAccessToken;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Checks no permission: whoever can call it already runs the deployment.
 */
final readonly class InitialAccessTokenIssuance
{
    public function __construct(
        private SecretDrawer $secrets,
        private InitialAccessTokenRepositoryInterface $tokens,
        private ClockInterface $clock,
    ) {
    }

    /**
     * @param string $name never empty
     * @param int $registrationsAllowed at least one
     *
     * @throws InvalidArgumentException
     */
    public function issue(Tenant $tenant, string $name, int $registrationsAllowed, DateInterval $validFor): IssuedInitialAccessToken
    {
        $value = $this->secrets->draw();
        $issuedAt = $this->clock->now();
        $token = new InitialAccessToken(
            Uuid::v7(),
            $tenant,
            DrawnSecret::digestOf($value),
            $name,
            $registrationsAllowed,
            $issuedAt,
            $issuedAt->add($validFor),
        );
        $this->tokens->save($token);

        return new IssuedInitialAccessToken($token, $value);
    }
}

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
 * A tenant hands somebody the right to register a client with it (RFC 7591 §1.2, decision 0009): a value
 * drawn like every other value this provider hands out, worth a number of registrations, expiring, and
 * named so that whoever issued it can say later which integration it was for.
 *
 * The value is answered once and the row holds its digest, which is the same rule the registration
 * answers its secret under: whoever reads the table holds nothing to present. So there is no second way
 * to obtain it, and a tenant that lost one issues another.
 *
 * Nothing here says who may issue one. A token is issued by whoever runs the deployment, at the console
 * and later at the tenant console (#194), both of which have the deployment already; the authority is
 * the reach of the machine, not a credential this provider checks.
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
     * @param string $name what the tenant calls this token; never empty
     * @param int $registrationsAllowed how many clients it may register; at least one
     * @param DateInterval $validFor how long it is worth anything, counted from now
     *
     * @throws InvalidArgumentException when what is asked for is not a token that holds together
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

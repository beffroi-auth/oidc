<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Domain\Event\InitialAccessTokenIssued;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Port\AdministrationResourceInterface;
use DateInterval;
use DateMalformedIntervalStringException;
use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Client\ClientMetadataReader;
use Beffroi\Oidc\Application\Secret\SecretDrawer;
use Beffroi\Oidc\Domain\Client\Metadata\GrantedMembers;
use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Client\Registration\IssuedInitialAccessToken;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use function in_array;
use function is_array;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use function sprintf;
use Symfony\Component\Uid\Uuid;

/**
 * Checks no permission: the console holds the authority of the host, and the administration API calls it for an
 * administrator it has found (decision 0038).
 */
final readonly class InitialAccessTokenIssuance
{
    /**
     * RFC 3339 §5.6 writes a year in four digits, as every date this provider answers is written.
     */
    private const string LAST_EXPIRY = '9999-12-31T23:59:59+00:00';

    public function __construct(
        private SecretDrawer $secrets,
        private InitialAccessTokenRepositoryInterface $tokens,
        private ClockInterface $clock,
        private ClientMetadataReader $reader,
        private AdministrationResourceInterface $administration,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * @param string $name never empty
     * @param int $registrationsAllowed at least one
     * @param int $days at least one, counted from now
     *
     * @throws InvalidArgumentException
     */
    public function issue(
        Tenant $tenant,
        string $name,
        int $registrationsAllowed,
        int $days,
        RequestContext $context,
        ?GrantedMembers $granted = null,
        bool $administration = false,
    ): IssuedInitialAccessToken {
        return $this->issueOnce($tenant, $name, $registrationsAllowed, $days, $context, null, $granted, $administration);
    }

    /**
     * The act names the administrator (decision 0038).
     *
     * @param string $name never empty
     * @param int $registrationsAllowed at least one
     * @param int $days at least one, counted from now
     *
     * @throws InvalidArgumentException
     */
    public function issueByAnAdministrator(
        Tenant $tenant,
        string $name,
        int $registrationsAllowed,
        int $days,
        Subject $administrator,
        RequestContext $context,
        ?GrantedMembers $granted = null,
        bool $administration = false,
    ): IssuedInitialAccessToken {
        return $this->issueOnce($tenant, $name, $registrationsAllowed, $days, $context, $administrator, $granted, $administration);
    }

    /**
     * @throws InvalidArgumentException
     */
    private function issueOnce(
        Tenant $tenant,
        string $name,
        int $registrationsAllowed,
        int $days,
        RequestContext $context,
        ?Subject $administrator,
        ?GrantedMembers $granted,
        bool $administration,
    ): IssuedInitialAccessToken {
        $api = $this->administration->administrationResourceOf($tenant);
        if ($administration && $api === null) {
            throw new InvalidArgumentException(sprintf(
                'The tenant "%s" names no administration API (BEFFROI_TENANT_ADMINISTRATION_RESOURCE): a token for its administration would register clients of nothing.',
                $tenant->slug,
            ));
        }
        if ($granted !== null) {
            $this->reader->assertGivable($name, $granted);
            self::assertGivesNoAdministrationResource($name, $granted, $api, $administration);
        }
        $issuedAt = $this->clock->now();
        $expiresAt = self::expiry($issuedAt, $days);
        $value = $this->secrets->draw();
        $token = new InitialAccessToken(
            Uuid::v7(),
            $tenant,
            DrawnSecret::digestOf($value),
            $name,
            $registrationsAllowed,
            $issuedAt,
            $expiresAt,
            $granted,
            $administration,
        );
        $this->tokens->save($token);
        $this->events->dispatch(new InitialAccessTokenIssued($issuedAt, $tenant, $token->id, $context, $administrator));

        return new IssuedInitialAccessToken($token, $value);
    }

    /**
     * @throws InvalidArgumentException
     */
    private static function expiry(DateTimeImmutable $issuedAt, int $days): DateTimeImmutable
    {
        if ($days < 1) {
            throw new InvalidArgumentException('An initial access token is worth something for a day at least.');
        }
        try {
            $expiresAt = $issuedAt->add(new DateInterval(sprintf('P%dD', $days)));
        } catch (DateMalformedIntervalStringException) {
            $expiresAt = null;
        }
        if ($expiresAt === null || $expiresAt > new DateTimeImmutable(self::LAST_EXPIRY)) {
            throw new InvalidArgumentException('An initial access token expires within the year 9999 at the latest, the last a date of RFC 3339 writes (section 5.6).');
        }

        return $expiresAt;
    }

    /**
     * Decision 0038. The resources a token gives would hide the API a client of the administration is given.
     *
     * @throws InvalidArgumentException
     */
    private static function assertGivesNoAdministrationResource(string $name, GrantedMembers $granted, ?ResourceIndicator $api, bool $administration): void
    {
        $resources = $granted->members()['resources'] ?? null;
        if (! is_array($resources)) {
            return;
        }
        if ($administration) {
            throw new InvalidArgumentException(sprintf(
                'The token "%s" is issued for the administration of the tenant, whose clients are given its administration API and no other resource (decision 0038).',
                $name,
            ));
        }
        if ($api !== null && in_array($api->value, $resources, true)) {
            throw new InvalidArgumentException(sprintf(
                'The token "%s" names the administration API of the tenant among its resources, which only a token issued for the administration gives, to clients that authenticate with a key (decision 0038).',
                $name,
            ));
        }
    }
}

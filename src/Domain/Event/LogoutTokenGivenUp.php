<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

/**
 * A logout token will not be delivered: the client refused it, or it could not be reached for as long as
 * the integration tries (Back-Channel Logout 1.0 §2.8). What the provider gives up on is said, never
 * kept quiet: the session is closed here whatever the client does with it, and someone has to be able to
 * see that a relying party was left believing its user is signed in. The token itself is not carried.
 */
final readonly class LogoutTokenGivenUp implements ConcernsAClientInterface
{
    /**
     * The name of the act, which is what the journal writes down (issue #454).
     */
    public const string NAME = 'logout_token.given_up';

    /**
     * @param string $clientId the client that was to be told, named as the grants name it
     * @param string $reason what the last attempt came back with
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public RequestContext $context,
        public string $clientId,
        public Uuid $sessionId,
        public string $reason,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }
}

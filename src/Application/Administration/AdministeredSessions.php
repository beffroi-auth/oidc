<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Domain\Event\SessionsReadByAnAdministrator;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The sessions open in the name of a person of the tenant, read by an administrator through the administration API
 * (decision 0038): what `beffroi:user:sessions` reads. The read delivers the person, so it is an act of theirs that
 * names the administrator (`SessionsReadByAnAdministrator`, decision 0022), and it is one whether they have a session
 * open or none, the answer saying of them that they have none.
 */
final readonly class AdministeredSessions
{
    public function __construct(
        private PersonsOfTheTenant $persons,
        private AuthenticationSessionRepositoryInterface $sessions,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * @return list<AuthenticationSession>|null null when the tenant has no person of that identifier
     */
    public function of(ActingAdministrator $administrator, Uuid $person, RequestContext $context): ?array
    {
        $user = $this->persons->find($administrator->tenant, $person);
        if ($user === null) {
            return null;
        }
        $sessions = $this->sessions->findActiveByUser($user, $context->receivedAt);
        $this->events->dispatch(new SessionsReadByAnAdministrator(
            $context->receivedAt,
            $administrator->tenant,
            $administrator->clientId,
            $user->subject,
            $administrator->user->subject,
            $context,
        ));

        return $sessions;
    }
}

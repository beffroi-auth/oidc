<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Port\CanFindUnendedSessionsInterface;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Domain\Event\SessionsReadByAnAdministrator;
use Beffroi\Oidc\Exception\PersonsBudgetSpentException;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The sessions of a person of the tenant that have not ended, read by an administrator through the administration API
 * (decision 0038): one past its expiry among them, whose refresh tokens still live (decision 0031), so that the
 * administrator sees every session an end would cut. The read delivers the person, so it is an act of theirs that
 * names the administrator (`SessionsReadByAnAdministrator`, decision 0022), and it is one whether they have a session
 * or none, the answer saying of them that they have none.
 */
final readonly class AdministeredSessions
{
    public function __construct(
        private PersonsOfTheTenant $persons,
        private CanFindUnendedSessionsInterface $sessions,
        private EventDispatcherInterface $events,
        private PersonsDelivered $delivered,
    ) {
    }

    /**
     * @throws PersonsBudgetSpentException when the budget of the administrator has no person left
     *
     * @return list<AuthenticationSession>|null null when the tenant has no person of that identifier
     */
    public function of(ActingAdministrator $administrator, Uuid $person, RequestContext $context): ?array
    {
        $user = $this->persons->find($administrator->tenant, $person);
        if ($user === null) {
            return null;
        }
        $this->delivered->spend($administrator, 1, $context);
        $sessions = $this->sessions->findUnendedByUser($user);
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

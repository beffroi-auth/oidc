<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use function array_find;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Application\Consent\ConsentRevocation;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Domain\Administration\ReadConsents;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Event\ConsentsReadByAnAdministrator;
use Beffroi\Oidc\Port\ActiveConsentsInterface;
use Beffroi\Oidc\Exception\PersonsBudgetSpentException;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The consents of a person of the tenant, read and taken back by an administrator through the administration API, on
 * what `beffroi:user:applications` and `beffroi:user:revoke-consent` call (decision 0038). Reading them delivers the
 * person, so it is an act of theirs that names the administrator (decision 0022); taking one back is an act of theirs
 * that names them too, which revokes what was issued under it.
 */
final readonly class AdministeredConsents
{
    public function __construct(
        private PersonsOfTheTenant $persons,
        private ActiveConsentsInterface $consents,
        private ConsentRevocation $revocation,
        private EventDispatcherInterface $events,
        private PersonsDelivered $delivered,
    ) {
    }

    /**
     * @throws PersonsBudgetSpentException when the budget of the administrator has no person left
     *
     * @return ReadConsents|null null when the tenant has no person of that identifier
     */
    public function of(ActingAdministrator $administrator, Uuid $person, RequestContext $context): ?ReadConsents
    {
        $user = $this->persons->find($administrator->tenant, $person);
        if ($user === null) {
            return null;
        }
        $this->delivered->spend($administrator, 1, $context);
        $read = new ReadConsents($user, $this->consents->activeOf($user));
        $this->events->dispatch(new ConsentsReadByAnAdministrator(
            $context->receivedAt,
            $administrator->tenant,
            $administrator->clientId,
            $user->subject,
            $administrator->user->subject,
            $context,
        ));

        return $read;
    }

    /**
     * @return Consent|null the consent taken back, null when the tenant has no such person or the person no such consent in force
     */
    public function revoke(ActingAdministrator $administrator, Uuid $person, Uuid $consent, RequestContext $context): ?Consent
    {
        $user = $this->persons->find($administrator->tenant, $person);
        if ($user === null) {
            return null;
        }
        $found = array_find($this->consents->activeOf($user), static fn (Consent $held): bool => $held->id->equals($consent));
        if ($found !== null) {
            $this->revocation->revokeByAnAdministrator($found, $administrator->user->subject, $context);
        }

        return $found;
    }
}

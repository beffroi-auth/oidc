<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\GroupsOfAPersonInterface;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Domain\Administration\ReadPerson;
use Beffroi\Oidc\Exception\PersonsBudgetSpentException;
use function trim;

/**
 * A person of the tenant read by an administrator through the administration API, by their username (decision 0038):
 * the account, its credentials and its groups, what `beffroi:user:show` reads. The read delivers the person, so it is
 * an act of theirs that names the administrator (`PersonReadByAnAdministrator`, decision 0022); a username nobody of
 * the tenant answers to delivers nobody and writes nothing.
 */
final readonly class AdministeredPerson
{
    public function __construct(
        private PersonsOfTheTenant $persons,
        private CredentialRepositoryInterface $credentials,
        private GroupsOfAPersonInterface $groups,
        private PersonDelivery $delivery,
        private PersonsDelivered $delivered,
    ) {
    }

    /**
     * @throws PersonsBudgetSpentException when the budget of the administrator has no person left
     */
    public function named(ActingAdministrator $administrator, string $username, RequestContext $context): ?ReadPerson
    {
        $user = $this->persons->named($administrator->tenant, trim($username));
        if ($user === null) {
            return null;
        }
        $this->delivered->spend($administrator, 1, $context);
        $read = new ReadPerson($user, $this->credentials->findByUser($user), $this->groups->of($user));
        $this->delivery->to($administrator, $user, $context);

        return $read;
    }
}

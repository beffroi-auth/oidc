<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Application\Identity\PersonDescription;
use Beffroi\Core\Application\Identity\UserAlreadyExistsException;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Exception\PersonsBudgetSpentException;
use Symfony\Component\Uid\Uuid;

/**
 * What an administrator says of a person of the tenant through the administration API (decision 0038): each value that
 * changed is a row of the history of the person, and the description one act of theirs, both naming the administrator.
 * A description that changes nothing answers the person as they are, which is a read of them (decision 0022). The
 * answer delivers the person, so it spends one person of the budget of the administrator first (decision 0014).
 */
final readonly class AdministeredDescription
{
    public function __construct(
        private PersonsOfTheTenant $persons,
        private PersonDescription $description,
        private PersonDelivery $delivery,
        private PersonsDelivered $delivered,
    ) {
    }

    /**
     * @param array<string, mixed> $said the value of each member said, by its name in the document of a person
     *
     * @throws InvalidArgumentException  when a member is not one an administrator says, a value is not one it holds, or the source of the person holds it
     * @throws UserAlreadyExistsException when another person of the tenant has the username said
     * @throws PersonsBudgetSpentException when the budget of the administrator has no person left
     *
     * @return User|null the person as they now are, null when the tenant has no person of that identifier
     */
    public function describe(ActingAdministrator $administrator, Uuid $person, array $said, RequestContext $context): ?User
    {
        $user = $this->persons->find($administrator->tenant, $person);
        if ($user !== null) {
            $this->delivered->spend($administrator, 1, $context);
            if ($this->description->describeByAnAdministrator($user, $said, $administrator->user->subject, $context) === []) {
                $this->delivery->to($administrator, $user, $context);
            }
        }

        return $user;
    }
}

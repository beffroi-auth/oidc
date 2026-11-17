<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Application\Identity\PersonDescription;
use Beffroi\Core\Application\Identity\UserAlreadyExistsException;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Symfony\Component\Uid\Uuid;

/**
 * What an administrator says of a person of the tenant through the administration API (decision 0038): each value that
 * changed is a row of the history of the person, and the description one act of theirs, both naming the administrator.
 */
final readonly class AdministeredDescription
{
    public function __construct(
        private PersonsOfTheTenant $persons,
        private PersonDescription $description,
    ) {
    }

    /**
     * @param array<string, mixed> $said the value of each member said, by its name in the document of a person
     *
     * @throws InvalidArgumentException  when a member is not one an administrator says, a value is not one it holds, or the source of the person holds it
     * @throws UserAlreadyExistsException when another person of the tenant has the username said
     *
     * @return User|null the person as they now are, null when the tenant has no person of that identifier
     */
    public function describe(ActingAdministrator $administrator, Uuid $person, array $said, RequestContext $context): ?User
    {
        $user = $this->persons->find($administrator->tenant, $person);
        if ($user !== null) {
            $this->description->describeByAnAdministrator($user, $said, $administrator->user->subject, $context);
        }

        return $user;
    }
}

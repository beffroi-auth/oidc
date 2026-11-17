<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Application\Identity\PersonCreation;
use Beffroi\Core\Application\Identity\UserAlreadyExistsException;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;

/**
 * A person of the tenant, created by an administrator through the administration API on the use case
 * `beffroi:user:create` calls (decision 0038): the creation is an act of their account that names the administrator.
 */
final readonly class AdministeredPersonCreation
{
    public function __construct(
        private PersonCreation $creation,
    ) {
    }

    /**
     * @throws UserAlreadyExistsException
     * @throws InvalidArgumentException   when the username is empty or longer than 255 characters
     */
    public function create(
        ActingAdministrator $administrator,
        string $username,
        RequestContext $context,
        ?EmailAddress $email = null,
        bool $emailVerified = false,
    ): User {
        return $this->creation->createByAnAdministrator(
            $administrator->tenant,
            $username,
            $administrator->user->subject,
            $context,
            $email,
            $emailVerified,
        );
    }
}

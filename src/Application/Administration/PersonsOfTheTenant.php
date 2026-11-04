<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\UserRepositoryInterface;
use Symfony\Component\Uid\Uuid;

/**
 * A person of the tenant an administrator administers, by the identifier of their account, and nobody of another
 * tenant whatever identifier is asked (decision 0038): an administrator reads the people of their own tenant only.
 */
final readonly class PersonsOfTheTenant
{
    public function __construct(
        private UserRepositoryInterface $users,
    ) {
    }

    public function find(Tenant $tenant, Uuid $id): ?User
    {
        $user = $this->users->find($id);

        return $user !== null && $user->belongsTo($tenant) ? $user : null;
    }

    public function named(Tenant $tenant, string $username): ?User
    {
        return $this->users->findByUsername($tenant, $username);
    }
}

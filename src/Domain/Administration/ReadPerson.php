<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Administration;

use Beffroi\Core\Domain\Credential\Credential;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Identity\User;

/**
 * A person of the tenant as an administrator reads them through the administration API (decision 0038): the account
 * with the claims it holds, the credentials it signs in with, and the groups it is in with the source of each
 * membership. What `beffroi:user:show` prints.
 */
final readonly class ReadPerson
{
    /**
     * @param list<Credential>      $credentials
     * @param list<GroupMembership> $memberships
     */
    public function __construct(
        public User $user,
        public array $credentials,
        public array $memberships,
    ) {
    }
}

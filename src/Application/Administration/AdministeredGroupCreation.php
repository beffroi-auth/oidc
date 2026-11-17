<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Application\Group\GroupProvisioner;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Exception\GroupAlreadyExistsException;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Port\AdministratorGroupsInterface;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Domain\Administration\CountedGroup;
use function in_array;

/**
 * A group of the tenant created by an administrator through the administration API, on the use case
 * `beffroi:group:create` calls (decision 0038): the act names the administrator.
 */
final readonly class AdministeredGroupCreation
{
    public function __construct(
        private GroupProvisioner $provisioner,
        private AdministratorGroupsInterface $administrators,
    ) {
    }

    /**
     * @throws GroupAlreadyExistsException when the tenant has a group of that name already
     * @throws InvalidArgumentException    when the name is empty, too long, not in NFC, or begins or ends with whitespace
     */
    public function create(ActingAdministrator $administrator, string $name, RequestContext $context): CountedGroup
    {
        $group = $this->provisioner->createByAnAdministrator($administrator->tenant, $name, $administrator->user->subject, $context);

        return new CountedGroup($group, 0, in_array($group->name, $this->administrators->groupsAdministering($administrator->tenant), true));
    }
}

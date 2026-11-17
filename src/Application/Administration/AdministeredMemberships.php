<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use function array_any;
use Beffroi\Core\Application\Group\LocalMemberships;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Exception\GroupMembershipException;
use Beffroi\Core\Port\AdministratorGroupsInterface;
use Beffroi\Core\Port\GroupsOfAPersonInterface;
use Beffroi\Core\Port\GroupsOfATenantInterface;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Exception\OwnAccountRefusedException;
use function in_array;
use Symfony\Component\Uid\Uuid;

/**
 * The members the tenant holds itself in its groups, given and taken back by an administrator through the
 * administration API, on the use case `beffroi:group:add-member` and `beffroi:group:remove-member` call (decision
 * 0038): each change is an act of the person that names the administrator. An administrator does not take themselves
 * out of a group whose members administer the tenant.
 */
final readonly class AdministeredMemberships
{
    public function __construct(
        private GroupsOfATenantInterface $groups,
        private PersonsOfTheTenant $persons,
        private GroupsOfAPersonInterface $groupsOfAPerson,
        private LocalMemberships $memberships,
        private AdministratorGroupsInterface $administrators,
    ) {
    }

    /**
     * @throws GroupMembershipException when a directory fills the group, or the person already is one of its members
     *
     * @return GroupMembership|null null when the tenant has no group of that identifier or no person of that username
     */
    public function add(ActingAdministrator $administrator, Uuid $group, string $username, RequestContext $context): ?GroupMembership
    {
        $found = $this->groups->find($administrator->tenant, $group);
        $user = $this->persons->named($administrator->tenant, $username);
        if ($found === null || $user === null) {
            return null;
        }

        return $this->memberships->addByAnAdministrator($found, $user, $administrator->user->subject, $context);
    }

    /**
     * @throws GroupMembershipException   when the person is a member by a directory, which alone takes them back
     * @throws OwnAccountRefusedException when the person is the administrator and the group makes them one
     *
     * @return Group|null the group they left, null when the tenant has no such group, or the person is not one of its members
     */
    public function remove(ActingAdministrator $administrator, Uuid $group, Uuid $person, RequestContext $context): ?Group
    {
        $found = $this->groups->find($administrator->tenant, $group);
        $user = $this->persons->find($administrator->tenant, $person);
        if ($found === null || $user === null || ! $this->isAMember($found, $user)) {
            return null;
        }
        if ($user->id->equals($administrator->user->id) && in_array($found->name, $this->administrators->groupsAdministering($administrator->tenant), true)) {
            throw new OwnAccountRefusedException('An administrator does not take themselves out of a group whose members administer the tenant.');
        }
        $this->memberships->removeByAnAdministrator($found, $user, $administrator->user->subject, $context);

        return $found;
    }

    private function isAMember(Group $group, User $user): bool
    {
        return array_any(
            $this->groupsOfAPerson->of($user),
            static fn (GroupMembership $membership): bool => $membership->group->id->equals($group->id),
        );
    }
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use function array_map;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Port\AdministratorGroupsInterface;
use Beffroi\Core\Port\GroupsOfATenantInterface;
use Beffroi\Core\Port\MembersOfAGroupInterface;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Domain\Administration\CountedGroup;
use Beffroi\Oidc\Domain\Event\MembershipReadByAnAdministrator;
use function in_array;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The groups of the tenant read by an administrator through the administration API (decision 0038). Counting the
 * members of a group delivers none of them; reading them delivers each one, so each is an act of theirs that names the
 * administrator (decision 0022).
 */
final readonly class AdministeredGroups
{
    public function __construct(
        private GroupsOfATenantInterface $groups,
        private MembersOfAGroupInterface $members,
        private AdministratorGroupsInterface $administrators,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * @return list<CountedGroup> by name
     */
    public function all(ActingAdministrator $administrator): array
    {
        $administering = $this->administrators->groupsAdministering($administrator->tenant);

        return array_map(
            fn (Group $group): CountedGroup => new CountedGroup($group, $this->members->countMembersOf($group), in_array($group->name, $administering, true)),
            $this->groups->of($administrator->tenant),
        );
    }

    /**
     * @return list<GroupMembership>|null the members in the order they were added, null when the tenant has no group of that identifier
     */
    public function members(ActingAdministrator $administrator, Uuid $group, RequestContext $context): ?array
    {
        $found = $this->groups->find($administrator->tenant, $group);
        if ($found === null) {
            return null;
        }
        $members = $this->members->membersOf($found);
        foreach ($members as $membership) {
            $this->events->dispatch(new MembershipReadByAnAdministrator(
                $context->receivedAt,
                $administrator->tenant,
                $administrator->clientId,
                $membership->user->subject,
                $administrator->user->subject,
                $context,
            ));
        }

        return $members;
    }
}

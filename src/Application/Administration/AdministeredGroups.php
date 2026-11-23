<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use function array_map;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupMembership;
use Beffroi\Core\Domain\Listing\Listing;
use Beffroi\Core\Domain\Listing\Pagination;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Port\AdministratorGroupsInterface;
use Beffroi\Core\Port\GroupsOfATenantInterface;
use Beffroi\Core\Port\MembersOfAGroupInterface;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Domain\Administration\CountedGroup;
use Beffroi\Oidc\Domain\Event\MembershipReadByAnAdministrator;
use Beffroi\Oidc\Exception\PersonsBudgetSpentException;
use function count;
use function in_array;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The groups of the tenant read by an administrator through the administration API (decision 0038). Counting the
 * members of a group delivers none of them; reading them delivers each one, a page at a time, so each is an act of
 * theirs that names the administrator (decision 0022) and spends one person of the budget of the administrator
 * (decision 0059).
 */
final readonly class AdministeredGroups
{
    /**
     * How many members a page holds when the administrator names no size.
     */
    public const int PAGE = 50;

    /**
     * The most members one page holds, whatever the administrator asks: one request never delivers a group whole.
     */
    public const int LARGEST_PAGE = 100;

    public function __construct(
        private GroupsOfATenantInterface $groups,
        private MembersOfAGroupInterface $members,
        private AdministratorGroupsInterface $administrators,
        private EventDispatcherInterface $events,
        private PersonsDelivered $delivered,
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
     * @throws PersonsBudgetSpentException when the page holds more persons than the budget of the administrator has left
     *
     * @return Listing<GroupMembership>|null the members in the order they were added, none on a page past the last one, null when the tenant has no group of that identifier
     */
    public function members(ActingAdministrator $administrator, Uuid $group, Pagination $page, RequestContext $context): ?Listing
    {
        $found = $this->groups->find($administrator->tenant, $group);
        if ($found === null) {
            return null;
        }
        $members = $this->members->membersOf($found, $page);
        if ($members->pagination->number !== $page->number) {
            return new Listing([], $page, $members->total);
        }
        $this->delivered->spend($administrator, count($members), $context);
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

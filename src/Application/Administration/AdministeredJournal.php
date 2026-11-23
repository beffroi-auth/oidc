<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Domain\Journal\JournalQuestion;
use Beffroi\Core\Domain\Listing\Pagination;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Port\CanPageActsOfAPersonInterface;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Domain\Event\JournalReadByAnAdministrator;
use Beffroi\Oidc\Exception\PersonsBudgetSpentException;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The last acts of a person of the tenant, every act whatever its name and its application, the most recent first,
 * read by an administrator through the administration API (decision 0038): what `beffroi:user:journal` reads over the
 * whole of what the journal holds. The read delivers the person, so it is an act of theirs that names the
 * administrator (`JournalReadByAnAdministrator`, decision 0022), written after the acts were read, so that the read
 * is not among what it answers.
 */
final readonly class AdministeredJournal
{
    /**
     * How many acts a read answers, the most recent ones.
     */
    public const int LAST = 50;

    public function __construct(
        private PersonsOfTheTenant $persons,
        private CanPageActsOfAPersonInterface $acts,
        private EventDispatcherInterface $events,
        private PersonsDelivered $delivered,
    ) {
    }

    /**
     * @throws PersonsBudgetSpentException when the budget of the administrator has no person left
     *
     * @return list<JournalEntry>|null null when the tenant has no person of that identifier
     */
    public function of(ActingAdministrator $administrator, Uuid $person, RequestContext $context): ?array
    {
        $user = $this->persons->find($administrator->tenant, $person);
        if ($user === null) {
            return null;
        }
        $this->delivered->spend($administrator, 1, $context);
        $acts = [];
        foreach ($this->acts->pageOfActs($user, new JournalQuestion(), new Pagination(1, self::LAST)) as $entry) {
            $acts[] = $entry;
        }
        $this->events->dispatch(new JournalReadByAnAdministrator(
            $context->receivedAt,
            $administrator->tenant,
            $administrator->clientId,
            $user->subject,
            $administrator->user->subject,
            $context,
        ));

        return $acts;
    }
}

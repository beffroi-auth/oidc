<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Domain\Event\ReadRefusedToAnAdministrator;
use Beffroi\Oidc\Exception\PersonsBudgetSpentException;
use Beffroi\Oidc\Port\PersonsBudgetInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * The persons a read of the administration API is about to deliver, spent from the budget of the administrator before
 * any of them is answered or written down as read (decision 0059): a read past the budget delivers nobody, and its
 * refusal is an act of the administrator.
 */
final readonly class PersonsDelivered
{
    public function __construct(
        private PersonsBudgetInterface $budget,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * @throws PersonsBudgetSpentException
     */
    public function spend(ActingAdministrator $administrator, int $persons, RequestContext $context): void
    {
        if ($persons < 1) {
            return;
        }
        try {
            $this->budget->spend($administrator, $persons);
        } catch (PersonsBudgetSpentException $spent) {
            $this->events->dispatch(new ReadRefusedToAnAdministrator(
                $context->receivedAt,
                $administrator->tenant,
                $administrator->clientId,
                $administrator->user->subject,
                $context,
            ));

            throw $spent;
        }
    }
}

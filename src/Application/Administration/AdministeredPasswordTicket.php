<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Application\Ticket\PasswordTicketIssue;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Ticket\IssuedTicket;
use Beffroi\Core\Domain\Ticket\PasswordTicket;
use Beffroi\Core\Exception\TicketRefusedException;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Symfony\Component\Uid\Uuid;

/**
 * The password ticket of a person of the tenant, issued by an administrator through the administration API on the use
 * case `beffroi:user:password-ticket` calls (decisions 0026 and 0038): it takes away the password tickets the person
 * had not spent, and the act of its issuing names the administrator.
 */
final readonly class AdministeredPasswordTicket
{
    public function __construct(
        private PersonsOfTheTenant $persons,
        private PasswordTicketIssue $tickets,
    ) {
    }

    /**
     * @return IssuedTicket<PasswordTicket>|null the ticket and the value its link carries, null when the tenant has no person of that identifier
     *
     * @throws TicketRefusedException when the person cannot sign in at all, or would be refused a password
     */
    public function issue(ActingAdministrator $administrator, Uuid $person, RequestContext $context): ?IssuedTicket
    {
        $user = $this->persons->find($administrator->tenant, $person);

        return $user === null ? null : $this->tickets->issueByAnAdministrator($user, $administrator->user->subject, $context);
    }
}

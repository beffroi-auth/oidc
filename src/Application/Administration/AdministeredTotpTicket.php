<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Application\Ticket\TotpTicketIssue;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Ticket\IssuedTicket;
use Beffroi\Core\Domain\Ticket\TotpTicket;
use Beffroi\Core\Exception\TicketRefusedException;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Symfony\Component\Uid\Uuid;

/**
 * The one-time password ticket of a person of the tenant, issued by an administrator through the administration API
 * on the use case `beffroi:user:totp-ticket` calls (decisions 0026 and 0038): it takes away the one-time password
 * tickets the person had not spent, and the act of its issuing names the administrator.
 */
final readonly class AdministeredTotpTicket
{
    public function __construct(
        private PersonsOfTheTenant $persons,
        private TotpTicketIssue $tickets,
    ) {
    }

    /**
     * @return IssuedTicket<TotpTicket>|null the ticket and the value its link carries, null when the tenant has no person of that identifier
     *
     * @throws TicketRefusedException when the person cannot sign in at all, or would be refused an authenticator app
     */
    public function issue(ActingAdministrator $administrator, Uuid $person, RequestContext $context): ?IssuedTicket
    {
        $user = $this->persons->find($administrator->tenant, $person);

        return $user === null ? null : $this->tickets->issueByAnAdministrator($user, $administrator->user->subject, $context);
    }
}

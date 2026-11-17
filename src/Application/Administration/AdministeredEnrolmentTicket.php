<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Application\Enrolment\EnrolmentTicketIssue;
use Beffroi\Core\Domain\Enrolment\IssuedEnrolmentTicket;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Exception\EnrolmentTicketRefusedException;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Symfony\Component\Uid\Uuid;

/**
 * The enrolment ticket of a person of the tenant, issued by an administrator through the administration API on the use
 * case `beffroi:user:enrolment-ticket` calls (decisions 0026 and 0038): it takes away the tickets the person had not
 * spent, and the act of its issuing names the administrator.
 */
final readonly class AdministeredEnrolmentTicket
{
    public function __construct(
        private PersonsOfTheTenant $persons,
        private EnrolmentTicketIssue $tickets,
    ) {
    }

    /**
     * @return IssuedEnrolmentTicket|null the ticket and the value its link carries, null when the tenant has no person of that identifier
     *
     * @throws EnrolmentTicketRefusedException when the account of the person is disabled
     */
    public function issue(ActingAdministrator $administrator, Uuid $person, RequestContext $context): ?IssuedEnrolmentTicket
    {
        $user = $this->persons->find($administrator->tenant, $person);

        return $user === null ? null : $this->tickets->issueByAnAdministrator($user, $administrator->user->subject, $context);
    }
}

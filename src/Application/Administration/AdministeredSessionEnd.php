<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Application\Authentication\SessionTerminator;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Symfony\Component\Uid\Uuid;

/**
 * An open session of a person of the tenant, ended by an administrator through the administration API on the use case
 * `beffroi:user:revoke-session` calls (decision 0038): its relying parties are told by the back-channel, and the act of
 * its end names the administrator.
 */
final readonly class AdministeredSessionEnd
{
    public function __construct(
        private PersonsOfTheTenant $persons,
        private AuthenticationSessionRepositoryInterface $sessions,
        private SessionTerminator $terminator,
    ) {
    }

    /**
     * @return AuthenticationSession|null the session ended, null when the tenant has no person of that identifier or the person no open session of that identifier
     */
    public function end(ActingAdministrator $administrator, Uuid $person, Uuid $session, RequestContext $context): ?AuthenticationSession
    {
        $user = $this->persons->find($administrator->tenant, $person);
        $open = $user === null ? null : $this->sessions->find($session);
        if ($user === null || $open === null || ! $open->user->id->equals($user->id) || ! $open->isActive($context->receivedAt)) {
            return null;
        }
        $this->terminator->endByAnAdministrator($open, $administrator->user->subject, $context);

        return $open;
    }
}

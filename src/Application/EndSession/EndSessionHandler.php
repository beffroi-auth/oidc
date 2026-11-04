<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\EndSession;

use DateTimeImmutable;
use Beffroi\Core\Application\Authentication\SessionTerminator;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Oidc\Domain\EndSession\EndSessionDecision;
use Beffroi\Oidc\Domain\EndSession\EndSessionRequest;
use Beffroi\Oidc\Domain\EndSession\LoggedOut;
use Beffroi\Oidc\Domain\EndSession\LogoutConfirmationReason;
use Beffroi\Oidc\Domain\EndSession\LogoutConfirmationRequired;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\PresentedSubjectReaderInterface;
use Psr\Clock\ClockInterface;

/**
 * RP-Initiated Logout §2, §4, §6
 */
final readonly class EndSessionHandler
{
    public function __construct(
        private SessionTerminator $sessions,
        private PresentedSubjectReaderInterface $subjects,
        private ClockInterface $clock,
    ) {
    }

    public function begin(EndSessionRequest $request, ?AuthenticationSession $session, RequestContext $context): EndSessionDecision
    {
        $now = $this->clock->now();
        $session = self::active($request, $session, $now);
        if ($session === null) {
            return new LoggedOut($request, null, $request->redirect());
        }
        $reason = $this->confirmationReason($request, $session);
        if ($reason !== null) {
            return new LogoutConfirmationRequired($request, $session, $reason);
        }

        return $this->end($request, $session, $context);
    }

    public function confirm(EndSessionRequest $request, ?AuthenticationSession $session, RequestContext $context): LoggedOut
    {
        $now = $this->clock->now();
        $session = self::active($request, $session, $now);
        if ($session === null) {
            return new LoggedOut($request, null, $request->redirect());
        }

        return $this->end($request, $session, $context);
    }

    /**
     * RP-Initiated Logout §2
     *
     * The hint's "sub" is read back for its client (OIDC Core §8): a pairwise one is not the core's subject.
     */
    private function confirmationReason(EndSessionRequest $request, AuthenticationSession $session): ?LogoutConfirmationReason
    {
        $hint = $request->idTokenHint;
        if ($hint === null) {
            return $request->invalidIdTokenHint ? LogoutConfirmationReason::InvalidHint : LogoutConfirmationReason::NoHint;
        }
        $named = $request->client === null ? null : $this->subjects->findUser($request->client, $hint->subject);
        if ($named === null || ! $named->id->equals($session->user->id)) {
            return LogoutConfirmationReason::DifferentUser;
        }
        if ($hint->sessionId === null || ! $hint->sessionId->equals($session->id)) {
            return LogoutConfirmationReason::DifferentSession;
        }

        return null;
    }

    private static function active(EndSessionRequest $request, ?AuthenticationSession $session, DateTimeImmutable $now): ?AuthenticationSession
    {
        if ($session === null) {
            return null;
        }
        if (! $session->tenant->equals($request->tenant)) {
            throw new InvalidArgumentException('A logout request ends a session of its own tenant.');
        }

        return $session->isActive($now) ? $session : null;
    }

    private function end(EndSessionRequest $request, AuthenticationSession $session, RequestContext $context): LoggedOut
    {
        $this->sessions->end($session, SessionEnd::RelyingParty, $context);

        return new LoggedOut($request, $session, $request->redirect());
    }
}

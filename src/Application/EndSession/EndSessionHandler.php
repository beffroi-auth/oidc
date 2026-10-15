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
use Psr\Clock\ClockInterface;

/**
 * Decides what a logout request does to the session the browser holds (RP-Initiated Logout §2,
 * architecture §4.9): ends it without a question when the hint proves the request is about it, asks the
 * user otherwise (§2, §6), honours the request as is when there is no session (§4). Ending a session
 * goes through the SessionTerminator, and the tokens issued in it are revoked on the event every end
 * announces (SessionTokensRevocation, decision 0006), as those of a session ended anywhere else are.
 */
final readonly class EndSessionHandler
{
    public function __construct(
        private SessionTerminator $sessions,
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
        $reason = self::confirmationReason($request, $session);
        if ($reason !== null) {
            return new LogoutConfirmationRequired($request, $session, $reason);
        }

        return $this->end($request, $session, $context);
    }

    /**
     * After the confirmation page, when the user said yes: the session ends whatever the hint said (§2).
     */
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
     * §2: no hint, an unverifiable one, or one that does not belong to the current session and user.
     */
    private static function confirmationReason(EndSessionRequest $request, AuthenticationSession $session): ?LogoutConfirmationReason
    {
        $hint = $request->idTokenHint;
        if ($hint === null) {
            return $request->invalidIdTokenHint ? LogoutConfirmationReason::InvalidHint : LogoutConfirmationReason::NoHint;
        }
        if (! $session->user->subject->equals($hint->subject)) {
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

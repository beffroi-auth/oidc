<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\EndSession;

use DateTimeImmutable;
use Heidi\Core\Application\Authentication\SessionTerminator;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Oidc\Domain\EndSession\EndSessionDecision;
use Heidi\Oidc\Domain\EndSession\EndSessionRequest;
use Heidi\Oidc\Domain\EndSession\LoggedOut;
use Heidi\Oidc\Domain\EndSession\LogoutConfirmationReason;
use Heidi\Oidc\Domain\EndSession\LogoutConfirmationRequired;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Port\AccessTokenRepositoryInterface;
use Heidi\Oidc\Port\CanRevokeAccessTokensBySessionInterface;
use Heidi\Oidc\Port\RefreshTokenRepositoryInterface;
use Psr\Clock\ClockInterface;

/**
 * Decides what a validated logout request does to the session the browser holds (OIDC RP-Initiated
 * Logout 1.0 §2, architecture §4.9). The session ends without a question only when the hint proves
 * the request is about it: same user and same session as the "sid" of the hint. Otherwise §2 requires
 * asking the user, and §6 says why: a logout request without a valid hint is a denial of service in
 * waiting. The integration shows the confirmation page, which re-submits the same parameters, and calls
 * confirm() when the user said yes; there is nothing to park in between. When the browser holds no
 * active session, there is nothing to ask and nothing to end: the request is honoured as is (§4, a
 * logout request is idempotent).
 *
 * Ending a session goes through the SessionTerminator of the core, so that it leaves the same trace
 * as any other end (AuthenticationSessionEnded, ended by the relying party), and revokes every refresh
 * token issued in it, and every stored access token when the store can (CanRevokeAccessTokensBySessionInterface),
 * decision 0006: the grant and the verifier already refuse a token of an ended session, the revocation
 * makes it visible. These writes are the ones the protocol needs before answering (architecture §5.6).
 */
final readonly class EndSessionHandler
{
    public function __construct(
        private SessionTerminator $sessions,
        private RefreshTokenRepositoryInterface $refreshTokens,
        private AccessTokenRepositoryInterface $accessTokens,
        private ClockInterface $clock,
    ) {
    }

    /**
     * @param AuthenticationSession|null $session the session the browser is bound to, if any
     */
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

        return $this->end($request, $session, $context, $now);
    }

    /**
     * After the confirmation page, when the user said yes: the session ends whatever the hint said,
     * because the user, not the hint, is now the one asking (§2: "If the End-User says yes, then the
     * OP MUST log out the End-User").
     */
    public function confirm(EndSessionRequest $request, ?AuthenticationSession $session, RequestContext $context): LoggedOut
    {
        $now = $this->clock->now();
        $session = self::active($request, $session, $now);
        if ($session === null) {
            return new LoggedOut($request, null, $request->redirect());
        }

        return $this->end($request, $session, $context, $now);
    }

    /**
     * §2: the provider must ask when no id_token_hint was given, or when the hint does not belong to
     * the current session and user.
     */
    private static function confirmationReason(EndSessionRequest $request, AuthenticationSession $session): ?LogoutConfirmationReason
    {
        $hint = $request->idTokenHint;
        if ($hint === null) {
            return LogoutConfirmationReason::NoHint;
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

    private function end(EndSessionRequest $request, AuthenticationSession $session, RequestContext $context, DateTimeImmutable $now): LoggedOut
    {
        foreach ($this->refreshTokens->findBySession($session->id) as $token) {
            if ($token->isRevoked()) {
                continue;
            }
            $token->revoke($now);
            $this->refreshTokens->save($token);
        }
        if ($this->accessTokens instanceof CanRevokeAccessTokensBySessionInterface) {
            $this->accessTokens->revokeBySession($session->id);
        }
        $this->sessions->end($session, SessionEnd::RelyingParty, $context);

        return new LoggedOut($request, $session, $request->redirect());
    }
}

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\EndSession;

use Heidi\Core\Domain\Session\AuthenticationSession;

/**
 * The user is logged out of the provider: the session was ended now, or there was none to end, which
 * is the same outcome (OIDC RP-Initiated Logout 1.0 §4: a logout request is idempotent). The
 * integration drops what binds the browser to the session, then sends the user agent to the redirect
 * when there is one, or shows that they are logged out.
 */
final readonly class LoggedOut implements EndSessionDecision
{
    /**
     * @param AuthenticationSession|null $endedSession the session this request ended, null when the browser held no active one
     */
    public function __construct(
        public EndSessionRequest $request,
        public ?AuthenticationSession $endedSession,
        public ?PostLogoutRedirect $redirect,
    ) {
    }
}

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\EndSession;

use Heidi\Core\Domain\Session\AuthenticationSession;

/**
 * The session was ended now, or there was none to end (RP-Initiated Logout §4).
 */
final readonly class LoggedOut implements EndSessionDecision
{
    public function __construct(
        public EndSessionRequest $request,
        public ?AuthenticationSession $endedSession,
        public ?PostLogoutRedirect $redirect,
    ) {
    }
}

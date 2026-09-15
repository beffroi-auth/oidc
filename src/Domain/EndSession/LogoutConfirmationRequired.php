<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\EndSession;

use Heidi\Core\Domain\Session\AuthenticationSession;

/**
 * Show the confirmation page: the session is active and the request does not prove it is the one to
 * end. The page re-submits the same parameters with the user's answer; the handler reads them again and
 * ends the session on confirm(). Nothing is parked in between.
 */
final readonly class LogoutConfirmationRequired implements EndSessionDecision
{
    public function __construct(
        public EndSessionRequest $request,
        public AuthenticationSession $session,
        public LogoutConfirmationReason $reason,
    ) {
    }
}

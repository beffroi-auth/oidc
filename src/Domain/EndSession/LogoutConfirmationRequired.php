<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\EndSession;

use Beffroi\Core\Domain\Session\AuthenticationSession;

/**
 * Show the confirmation page, which re-submits the same parameters; nothing is parked in between.
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

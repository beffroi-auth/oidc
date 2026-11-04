<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\EndSession;

use Beffroi\Core\Domain\Session\AuthenticationSession;

final readonly class LoggedOut implements EndSessionDecision
{
    public function __construct(
        public EndSessionRequest $request,
        public ?AuthenticationSession $endedSession,
        public ?PostLogoutRedirect $redirect,
    ) {
    }
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\EndSession;

enum LogoutConfirmationReason: string
{
    case NoHint = 'no_hint';

    case InvalidHint = 'invalid_hint';

    case DifferentUser = 'different_user';

    /**
     * Another session of the same user, or none.
     */
    case DifferentSession = 'different_session';
}

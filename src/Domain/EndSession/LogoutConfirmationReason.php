<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\EndSession;

/**
 * Why the user is asked before their session ends (RP-Initiated Logout §2, §6).
 */
enum LogoutConfirmationReason: string
{
    case NoHint = 'no_hint';

    /**
     * A hint this provider cannot verify today (a retired key), treated as no hint (§6).
     */
    case InvalidHint = 'invalid_hint';

    case DifferentUser = 'different_user';

    /**
     * Another session of the same user, or none.
     */
    case DifferentSession = 'different_session';
}

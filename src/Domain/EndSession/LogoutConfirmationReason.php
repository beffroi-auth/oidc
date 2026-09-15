<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\EndSession;

/**
 * Why the user is asked before their session ends (OIDC RP-Initiated Logout 1.0 §2: the provider must
 * ask when no id_token_hint was given or when the hint does not describe the current session and user;
 * §6: a request without a valid hint is a potential denial of service). The confirmation page reads it
 * to say what it knows.
 */
enum LogoutConfirmationReason: string
{
    /**
     * The request carries no id_token_hint: nothing says which relying party asks, nor for whom.
     */
    case NoHint = 'no_hint';

    /**
     * The hint names another user than the one of the session.
     */
    case DifferentUser = 'different_user';

    /**
     * The hint names the user of the session but another session of theirs, or none.
     */
    case DifferentSession = 'different_session';
}

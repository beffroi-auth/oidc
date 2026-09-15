<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Interaction;

/**
 * Why the user has to authenticate before the request goes further. The login page reads it to say
 * "log in", "confirm it is you" or "choose an account"; with prompt=none it becomes "login_required".
 */
enum LoginRequirement: string
{
    /**
     * No session, or one that ended or expired.
     */
    case NoSession = 'no_session';

    /**
     * OIDC Core §3.1.2.1 prompt=login: the client asks for a re-authentication.
     */
    case ReauthenticationRequested = 'reauthentication_requested';

    /**
     * OIDC Core §3.1.2.1 prompt=select_account: the client asks the user to choose an account.
     */
    case AccountSelectionRequested = 'account_selection_requested';

    /**
     * OIDC Core §3.1.2.1 max_age: the last authentication is older than the client tolerates.
     */
    case MaxAgeExceeded = 'max_age_exceeded';

    /**
     * OIDC Core §3.1.2.1 id_token_hint: the session belongs to another user than the one the client names.
     */
    case DifferentUser = 'different_user';
}

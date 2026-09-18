<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Interaction;

/**
 * Why the user has to authenticate (OIDC Core §3.1.2.1); with prompt=none it becomes "login_required".
 */
enum LoginRequirement: string
{
    case NoSession = 'no_session';

    /**
     * prompt=login
     */
    case ReauthenticationRequested = 'reauthentication_requested';

    /**
     * prompt=select_account
     */
    case AccountSelectionRequested = 'account_selection_requested';

    /**
     * max_age
     */
    case MaxAgeExceeded = 'max_age_exceeded';

    /**
     * id_token_hint names another user than the one of the session
     */
    case DifferentUser = 'different_user';
}

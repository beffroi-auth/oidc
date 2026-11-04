<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Interaction;

/**
 * OIDC Core §3.1.2.1
 */
enum LoginRequirement: string
{
    case NoSession = 'no_session';

    /**
     * prompt=login
     */
    case ReauthenticationRequested = 'reauthentication_requested';

    case AccountSelectionRequested = 'account_selection_requested';

    case MaxAgeExceeded = 'max_age_exceeded';

    /**
     * id_token_hint names another user than the one of the session
     */
    case DifferentUser = 'different_user';

    /**
     * acr_values or the "acr" claim request names classes the provider can prove and the session satisfies none
     * (decision 0010)
     */
    case StrongerFactorRequired = 'stronger_factor_required';
}

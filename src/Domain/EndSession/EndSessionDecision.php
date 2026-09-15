<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\EndSession;

/**
 * What the end session handler tells the integration to do next (architecture §4.9): ask the user
 * whether to log out, or consider them logged out and send them on. An error in the request is not a
 * decision but an OAuth2Exception, shown to the user and never redirected (OIDC RP-Initiated Logout
 * 1.0 §4).
 */
interface EndSessionDecision
{
    public EndSessionRequest $request { get; }
}

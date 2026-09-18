<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\EndSession;

/**
 * What the end session handler tells the integration to do next (architecture §4.9). An error is an
 * OAuth2Exception, never redirected (RP-Initiated Logout §4).
 */
interface EndSessionDecision
{
    public EndSessionRequest $request { get; }
}

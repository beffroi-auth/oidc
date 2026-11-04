<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\EndSession;

/**
 * An error is no decision but an OAuth2Exception, never redirected (RP-Initiated Logout §4).
 */
interface EndSessionDecision
{
    public EndSessionRequest $request { get; }
}

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Interaction;

/**
 * What the authorization handler tells the integration to do next (architecture §4.3). An error is an
 * OAuth2Exception carrying the redirectable flag.
 */
interface AuthorizationDecision
{
    public Interaction $interaction { get; }
}

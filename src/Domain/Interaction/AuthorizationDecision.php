<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Interaction;

/**
 * What the authorization handler tells the integration to do next (architecture §4.3): send the user to
 * the login page, to the consent page, or back to the client with a code. An error that must reach the
 * client is not a decision but an OAuth2Exception carrying the redirectable flag.
 */
interface AuthorizationDecision
{
    public Interaction $interaction { get; }
}

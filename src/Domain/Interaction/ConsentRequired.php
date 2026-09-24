<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Interaction;

use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Oidc\Domain\Scope\Scopes;

/**
 * Send the user to the consent page, which calls grantConsent() or deny().
 */
final readonly class ConsentRequired implements AuthorizationDecision
{
    public function __construct(
        public Interaction $interaction,
        public AuthenticationSession $session,
        public Scopes $scopes,
        public ConsentRequirement $requirement,
    ) {
    }
}

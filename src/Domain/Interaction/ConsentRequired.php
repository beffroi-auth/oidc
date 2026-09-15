<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Interaction;

use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Oidc\Domain\Scope\Scope;

/**
 * Send the user to the consent page, which shows the client and the scopes and calls grantConsent() or
 * deny(). The interaction is saved and waits.
 */
final readonly class ConsentRequired implements AuthorizationDecision
{
    /**
     * @param list<Scope> $scopes what the client asks for, all of them: the user answers for the whole request
     */
    public function __construct(
        public Interaction $interaction,
        public AuthenticationSession $session,
        public array $scopes,
        public ConsentRequirement $requirement,
    ) {
    }
}

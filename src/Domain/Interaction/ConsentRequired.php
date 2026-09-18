<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Interaction;

use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Oidc\Domain\Scope\Scope;

/**
 * Send the user to the consent page, which calls grantConsent() or deny().
 */
final readonly class ConsentRequired implements AuthorizationDecision
{
    /**
     * @param list<Scope> $scopes the whole request; the user answers for all of them
     */
    public function __construct(
        public Interaction $interaction,
        public AuthenticationSession $session,
        public array $scopes,
        public ConsentRequirement $requirement,
    ) {
    }
}

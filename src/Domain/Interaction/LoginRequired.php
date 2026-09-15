<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Interaction;

/**
 * Send the user to the login page. The interaction is saved and waits for resume().
 */
final readonly class LoginRequired implements AuthorizationDecision
{
    public function __construct(
        public Interaction $interaction,
        public LoginRequirement $requirement,
    ) {
    }
}

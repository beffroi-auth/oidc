<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Interaction;

/**
 * Send the user to the login page, then resume().
 */
final readonly class LoginRequired implements AuthorizationDecision
{
    /**
     * @param StepUp|null $stepUp what the login has to add, with StrongerFactorRequired only
     */
    public function __construct(
        public Interaction $interaction,
        public LoginRequirement $requirement,
        public ?StepUp $stepUp = null,
    ) {
    }

    /**
     * The name of this decision, which the integration answers with its login page.
     */
    public function name(): string
    {
        return 'login';
    }
}

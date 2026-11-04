<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Interaction;

final readonly class LoginRequired implements AuthorizationDecision
{
    /**
     * @param StepUp|null $stepUp set with StrongerFactorRequired only
     */
    public function __construct(
        public Interaction $interaction,
        public LoginRequirement $requirement,
        public ?StepUp $stepUp = null,
    ) {
    }

    public function name(): string
    {
        return 'login';
    }
}

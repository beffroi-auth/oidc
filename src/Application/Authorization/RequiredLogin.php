<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use Beffroi\Oidc\Domain\Interaction\LoginRequirement;
use Beffroi\Oidc\Domain\Interaction\StepUp;

final readonly class RequiredLogin
{
    public function __construct(
        public LoginRequirement $requirement,
        public ?StepUp $stepUp = null,
    ) {
    }
}

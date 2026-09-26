<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Authorization;

use Heidi\Oidc\Domain\Interaction\LoginRequirement;
use Heidi\Oidc\Domain\Interaction\StepUp;

/**
 * What the authentication of an interaction still needs (architecture §4.3): why a login page is asked for,
 * and what it must ask the user for when what is missing is a stronger factor (decision 0010).
 *
 * It is not the decision the endpoint answers with: whether the page may be shown at all is prompt=none's
 * (OIDC Core §3.1.2.6), which the handler answers, so this says what is needed and never what to do about it.
 */
final readonly class RequiredLogin
{
    public function __construct(
        public LoginRequirement $requirement,
        public ?StepUp $stepUp = null,
    ) {
    }
}

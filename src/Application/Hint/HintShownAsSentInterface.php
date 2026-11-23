<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Hint;

use SensitiveParameter;

/**
 * Decision 0006
 *
 * A hint that is what the person types to sign in: the login page shows it as the client sent it, never after a
 * lookup, which would tell whether an account holds it.
 */
interface HintShownAsSentInterface extends UserHintInterface
{
    public function shownAsSent(#[SensitiveParameter] string $value): string;
}

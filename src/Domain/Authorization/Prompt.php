<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

/**
 * OIDC Core §3.1.2.1 "prompt"; "none" cannot be combined with another value.
 */
enum Prompt: string
{
    case None = 'none';
    case Login = 'login';
    case Consent = 'consent';
    case SelectAccount = 'select_account';
}

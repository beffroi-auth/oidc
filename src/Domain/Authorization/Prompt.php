<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

/**
 * OIDC Core §3.1.2.1 "prompt": what the client asks the provider to do, or not to do, with the end user.
 * Space delimited and case sensitive in the request. "none" cannot be combined with another value.
 */
enum Prompt: string
{
    case None = 'none';
    case Login = 'login';
    case Consent = 'consent';
    case SelectAccount = 'select_account';
}

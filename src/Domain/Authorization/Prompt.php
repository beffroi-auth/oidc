<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

/**
 * OIDC Core §3.1.2.1
 */
enum Prompt: string
{
    case None = 'none';
    case Login = 'login';
    case Consent = 'consent';
    case SelectAccount = 'select_account';
}

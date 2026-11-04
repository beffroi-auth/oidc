<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * OIDC Core §3.1.2.6
 */
final class LoginRequiredException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('login_required', $description, 400, true);
    }
}

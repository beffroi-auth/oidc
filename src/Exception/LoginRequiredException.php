<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * OIDC Core §3.1.2.6 "login_required": the request said prompt=none and the user is not authenticated,
 * or not as the request demands (prompt is read after the client and its redirect URI, so the error is
 * always sent back to the client).
 */
final class LoginRequiredException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('login_required', $description, 400, true);
    }
}

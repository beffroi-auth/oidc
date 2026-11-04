<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * RFC 6749 §4.1.2.1, RFC 8628 §3.5
 */
final class AccessDeniedException extends OAuth2Exception
{
    public function __construct(string $description, bool $redirectable = true)
    {
        parent::__construct('access_denied', $description, 400, $redirectable);
    }
}

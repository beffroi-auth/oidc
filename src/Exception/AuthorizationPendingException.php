<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * RFC 8628 §3.5
 */
final class AuthorizationPendingException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('authorization_pending', $description, 400, false);
    }
}

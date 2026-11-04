<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * RFC 8628 §3.5
 */
final class ExpiredTokenException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('expired_token', $description, 400, false);
    }
}

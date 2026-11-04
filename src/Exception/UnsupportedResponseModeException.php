<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * OAuth 2.0 Multiple Response Type Encoding Practices §2.1
 */
final class UnsupportedResponseModeException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('unsupported_response_mode', $description, 400, true);
    }
}

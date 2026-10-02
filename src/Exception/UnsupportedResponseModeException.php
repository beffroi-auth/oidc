<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * OAuth 2.0 Multiple Response Type Encoding Practices §2.1 "unsupported_response_mode": a response mode
 * the provider does not serve. The refusal goes back in the default mode, the only one it is sure the
 * client can read.
 */
final class UnsupportedResponseModeException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('unsupported_response_mode', $description, 400, true);
    }
}

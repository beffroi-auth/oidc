<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * RFC 6749 §5.2 "unsupported_grant_type": only "authorization_code" and "refresh_token" exist here
 * (decision 0006: no implicit, no password, no client credentials). The token endpoint answers 400.
 */
final class UnsupportedGrantTypeException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('unsupported_grant_type', $description, 400, false);
    }
}

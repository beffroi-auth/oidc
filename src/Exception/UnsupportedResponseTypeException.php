<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * RFC 6749 §4.1.2.1 "unsupported_response_type": the only response type is "code" (decision 0006: no
 * implicit, no hybrid). Raised by the authorization endpoint once the client and its redirect URI are
 * known, so it is always sent back to the client.
 */
final class UnsupportedResponseTypeException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('unsupported_response_type', $description, 400, true);
    }
}

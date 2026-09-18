<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * RFC 6749 §4.1.2.1 "unsupported_response_type": "code" only (decision 0006).
 */
final class UnsupportedResponseTypeException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('unsupported_response_type', $description, 400, true);
    }
}

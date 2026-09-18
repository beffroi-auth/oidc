<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use Throwable;

/**
 * RFC 6750 §3.1 "invalid_token": 401 with the challenge.
 */
final class InvalidTokenException extends OAuth2Exception
{
    public function __construct(string $description, ?Throwable $previous = null)
    {
        parent::__construct('invalid_token', $description, 401, false, $previous);
    }
}

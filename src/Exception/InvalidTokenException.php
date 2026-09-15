<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use Throwable;

/**
 * RFC 6750 §3.1 "invalid_token": the bearer token is expired, revoked, malformed, or invalid for another
 * reason; the resource answers 401 with the challenge, and the client may ask for a new token. Never a
 * redirect: only a protected resource raises it.
 */
final class InvalidTokenException extends OAuth2Exception
{
    public function __construct(string $description, ?Throwable $previous = null)
    {
        parent::__construct('invalid_token', $description, 401, false, $previous);
    }
}

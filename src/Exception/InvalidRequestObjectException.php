<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Throwable;

/**
 * OIDC Core §3.1.2.6, RFC 9101 §6.3
 *
 * Never redirected: a provider that has not read the request does not know where to send its refusal
 * (decision 0006).
 */
final class InvalidRequestObjectException extends OAuth2Exception
{
    public function __construct(string $description, ?Throwable $previous = null)
    {
        parent::__construct('invalid_request_object', $description, 400, false, $previous);
    }
}

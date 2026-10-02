<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Throwable;

/**
 * OIDC Core §3.1.2.6 and RFC 9101 §6.3 "invalid_request_object": the request object the client sent
 * cannot be read, is not signed the way the client registered, does not verify, or says something a
 * request object may not say. Never redirected: the request is read from the object before anything of
 * it is trusted, and a provider that has not read a request does not know where to send its refusal
 * (decision 0006). The endpoint that received it answers, a page or the JSON of RFC 6749 §5.2.
 */
final class InvalidRequestObjectException extends OAuth2Exception
{
    public function __construct(string $description, ?Throwable $previous = null)
    {
        parent::__construct('invalid_request_object', $description, 400, false, $previous);
    }
}

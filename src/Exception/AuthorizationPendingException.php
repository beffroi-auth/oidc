<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * RFC 8628 §3.5 "authorization_pending": the user has not answered yet, and the client keeps polling. It
 * is not a failure and says nothing more than "not yet": whether the user has even seen the code is not
 * something a polling client learns.
 */
final class AuthorizationPendingException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('authorization_pending', $description, 400, false);
    }
}

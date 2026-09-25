<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * RFC 6749 §4.1.2.1 "access_denied": the resource owner refused. Whether the refusal may be sent back to
 * the client is a property of where it was read: the authorization endpoint redirects it, the token
 * endpoint of a polling grant answers it in JSON (RFC 8628 §3.5) and redirects nothing anywhere.
 */
final class AccessDeniedException extends OAuth2Exception
{
    public function __construct(string $description, bool $redirectable = true)
    {
        parent::__construct('access_denied', $description, 400, $redirectable);
    }
}

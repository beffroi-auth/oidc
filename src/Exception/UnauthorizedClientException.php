<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * RFC 6749 §5.2 "unauthorized_client": not registered for the grant type.
 */
final class UnauthorizedClientException extends OAuth2Exception
{
    /**
     * @param bool $redirectable only from the authorization endpoint, once the redirect URI is known
     */
    public function __construct(string $description, bool $redirectable = false)
    {
        parent::__construct('unauthorized_client', $description, 400, $redirectable);
    }
}

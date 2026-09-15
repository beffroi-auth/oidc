<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * RFC 6749 §5.2 "unauthorized_client": the client authenticated, but is not registered for the grant type
 * it asks for. The token endpoint answers 400.
 */
final class UnauthorizedClientException extends OAuth2Exception
{
    /**
     * @param bool $redirectable true only from the authorization endpoint once the client and its redirect URI are known
     */
    public function __construct(string $description, bool $redirectable = false)
    {
        parent::__construct('unauthorized_client', $description, 400, $redirectable);
    }
}

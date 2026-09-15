<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * RFC 6749 §5.2 "invalid_request": a required parameter is missing, a parameter is repeated or malformed,
 * or the client used more than one authentication mechanism. The token endpoint answers 400.
 */
final class InvalidRequestException extends OAuth2Exception
{
    /**
     * @param bool $redirectable true only from the authorization endpoint once the client and its redirect URI are known
     */
    public function __construct(string $description, bool $redirectable = false)
    {
        parent::__construct('invalid_request', $description, 400, $redirectable);
    }
}

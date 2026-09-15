<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * RFC 6749 §4.1.2.1 and §5.2 "invalid_scope": the requested scope is malformed, unknown, not allowed to
 * this client, or does not contain "openid" (OIDC Core §3.1.2.2). The token endpoint answers 400.
 */
final class InvalidScopeException extends OAuth2Exception
{
    /**
     * @param bool $redirectable true only from the authorization endpoint once the client and its redirect URI are known
     */
    public function __construct(string $description, bool $redirectable = false)
    {
        parent::__construct('invalid_scope', $description, 400, $redirectable);
    }
}

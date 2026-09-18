<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use Throwable;

/**
 * RFC 6749 §4.1.2.1, §5.2 "invalid_scope".
 */
final class InvalidScopeException extends OAuth2Exception
{
    /**
     * @param bool $redirectable only from the authorization endpoint, once the redirect URI is known
     */
    public function __construct(string $description, bool $redirectable = false, ?Throwable $previous = null)
    {
        parent::__construct('invalid_scope', $description, 400, $redirectable, $previous);
    }
}

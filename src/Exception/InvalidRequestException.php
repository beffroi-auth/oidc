<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Throwable;

/**
 * RFC 6749 §5.2
 */
final class InvalidRequestException extends OAuth2Exception
{
    /**
     * @param bool $redirectable only from the authorization endpoint, once the redirect URI is known
     */
    public function __construct(string $description, bool $redirectable = false, ?Throwable $previous = null)
    {
        parent::__construct('invalid_request', $description, 400, $redirectable, $previous);
    }
}

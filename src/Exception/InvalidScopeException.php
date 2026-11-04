<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Throwable;

/**
 * RFC 6749 §4.1.2.1, §5.2
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

    /**
     * RFC 6749 §3.3
     */
    public static function notASpaceSeparatedList(bool $redirectable = false, ?Throwable $previous = null): self
    {
        return new self('The scope parameter is not a space-separated list of scope tokens (RFC 6749 section 3.3).', $redirectable, $previous);
    }

    /**
     * RFC 6749 §3.3
     *
     * The description names no scope, so that an error response teaches nothing of what the client registered.
     */
    public static function notRegistered(bool $redirectable = false): self
    {
        return new self('The requested scope is not allowed for this client.', $redirectable);
    }
}

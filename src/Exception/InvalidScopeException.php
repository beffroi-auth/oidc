<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

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

    /**
     * What a "scope" parameter must be wherever one is read (RFC 6749 §3.3): the authorization request
     * reads one, the refresh grant reads one, and both refuse the same thing the same way.
     */
    public static function notASpaceSeparatedList(bool $redirectable = false, ?Throwable $previous = null): self
    {
        return new self('The scope parameter is not a space-separated list of scope tokens (RFC 6749 section 3.3).', $redirectable, $previous);
    }

    /**
     * RFC 6749 §3.3: what a client may be granted is among what it registered, wherever a request is read
     * for it: the authorization request, the endpoints where a flow on another device or through a
     * backchannel starts, and every grant with nobody's browser in it. The description names no scope: what
     * the client registered is not something an error response teaches whoever sent the request.
     */
    public static function notRegistered(bool $redirectable = false): self
    {
        return new self('The requested scope is not allowed for this client.', $redirectable);
    }
}

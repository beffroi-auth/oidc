<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use Throwable;

/**
 * RFC 8707 §2 "invalid_target": the requested resource is invalid, missing, unknown, or malformed. It
 * answers an authorization request (§2.1) and a token request (§2.2) alike.
 */
final class InvalidTargetException extends OAuth2Exception
{
    /**
     * @param bool $redirectable only from the authorization endpoint, once the redirect URI is known
     */
    public function __construct(string $description, bool $redirectable = false, ?Throwable $previous = null)
    {
        parent::__construct('invalid_target', $description, 400, $redirectable, $previous);
    }

    /**
     * What a "resource" parameter must be wherever one is read (RFC 8707 §2): the authorization
     * request reads one, every grant of the token endpoint reads one, and all of them refuse the same
     * thing the same way.
     */
    public static function notAnAbsoluteUri(bool $redirectable = false, ?Throwable $previous = null): self
    {
        return new self(
            'The resource parameter is an absolute URI without a fragment component (RFC 8707 section 2).',
            $redirectable,
            $previous,
        );
    }

    /**
     * RFC 8707 §2.1: what a client may ask for is what it registered, as every other list of a client
     * is. The description names no resource: what the client registered is not something an error
     * response teaches whoever sent the request.
     */
    public static function notRegistered(bool $redirectable = false): self
    {
        return new self('The requested resource is not one this client is registered for (RFC 8707 section 2).', $redirectable);
    }

    /**
     * RFC 8707 §2.2: a token request narrows the resources of the authorization it spends, and never
     * widens them.
     */
    public static function notGranted(): self
    {
        return new self('The requested resource is not among the resources of this authorization (RFC 8707 section 2.2).');
    }
}

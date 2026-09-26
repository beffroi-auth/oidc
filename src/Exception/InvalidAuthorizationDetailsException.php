<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use Throwable;

/**
 * RFC 9396 §5 "invalid_authorization_details": the "authorization_details" of the request is not what it
 * must be. It answers an authorization request, a pushed one and a token request alike, as
 * "invalid_target" does for the resources beside it.
 *
 * The four ways of being wrong are one error: a malformed array, an object naming no type, a type nobody
 * serves and a type the client is not registered for. Which it was is the description, and the
 * description names neither the type nor what the client registered: what a client may ask for is not
 * something an error response teaches whoever sent the request.
 */
final class InvalidAuthorizationDetailsException extends OAuth2Exception
{
    /**
     * @param bool $redirectable only from the authorization endpoint, once the redirect URI is known
     */
    public function __construct(string $description, bool $redirectable = false, ?Throwable $previous = null)
    {
        parent::__construct('invalid_authorization_details', $description, 400, $redirectable, $previous);
    }

    /**
     * What an "authorization_details" must be wherever one is read (RFC 9396 §2): a JSON array of
     * objects, each naming in "type" a type this provider serves, each holding what that type accepts.
     */
    public static function notWhatItMustBe(bool $redirectable = false, ?Throwable $previous = null): self
    {
        return new self(
            'The authorization_details parameter is a JSON array of objects, each naming in type an authorization detail type this provider serves and holding what that type accepts (RFC 9396 section 2).',
            $redirectable,
            $previous,
        );
    }

    /**
     * RFC 9396 §11: what a client may ask for is the closed list of its registration, as every other list
     * of a client is.
     */
    public static function notRegistered(bool $redirectable = false): self
    {
        return new self(
            'The requested authorization detail type is not one this client is registered for (RFC 9396 section 11).',
            $redirectable,
        );
    }

    /**
     * RFC 9396 §7: a token request narrows the details of the authorization it spends, and never widens
     * them.
     */
    public static function notGranted(): self
    {
        return new self('The requested authorization detail is not among the details of this authorization (RFC 9396 section 7).');
    }
}

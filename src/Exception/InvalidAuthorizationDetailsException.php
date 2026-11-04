<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Throwable;

/**
 * RFC 9396 §5
 *
 * The description names neither the type nor what the client registered.
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
     * RFC 9396 §2
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
     * RFC 9396 §11
     */
    public static function notRegistered(bool $redirectable = false): self
    {
        return new self(
            'The requested authorization detail type is not one this client is registered for (RFC 9396 section 11).',
            $redirectable,
        );
    }

    /**
     * RFC 9396 §7
     */
    public static function notGranted(): self
    {
        return new self('The requested authorization detail is not among the details of this authorization (RFC 9396 section 7).');
    }
}

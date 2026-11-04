<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Throwable;

/**
 * RFC 8707 §2
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
     * RFC 8707 §2
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
     * RFC 8707 §2.1
     *
     * The description names no resource, so that an error response teaches nothing of what the client registered.
     */
    public static function notRegistered(bool $redirectable = false): self
    {
        return new self('The requested resource is not one this client is registered for (RFC 8707 section 2).', $redirectable);
    }

    /**
     * RFC 8707 §2
     *
     * A grant with nobody behind it is refused rather than given a token addressed to the client that asked.
     */
    public static function missing(): self
    {
        return new self('This grant type issues an access token for a resource, and the request names none (RFC 8707 section 2).');
    }

    /**
     * RFC 8707 §2.2
     */
    public static function notGranted(): self
    {
        return new self('The requested resource is not among the resources of this authorization (RFC 8707 section 2.2).');
    }
}

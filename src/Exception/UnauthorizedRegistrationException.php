<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use function sprintf;

/**
 * The request presents nothing that authorises a registration on this tenant (RFC 7591 §1.2): no initial
 * access token where one is required, or one this provider will not act on.
 *
 * It reads the same whatever gave it away, a header that carries none, a value nobody was handed, a
 * token already worth nothing, one that expired or one the tenant took back: whoever does not hold a
 * token of this tenant learns nothing about the one they presented (decision 0006). That is one refusal,
 * so it is written once here and never beside each check.
 */
final class UnauthorizedRegistrationException extends OAuth2Exception
{
    /**
     * RFC 6750 §1.2: how an initial access token is presented, and therefore how one should have been.
     */
    public const string SCHEME = 'Bearer';

    public function __construct()
    {
        parent::__construct(
            'invalid_token',
            'The request does not carry an initial access token of this tenant (RFC 7591 section 1.2).',
            401,
            false,
        );
    }

    /**
     * RFC 6750 §3: an endpoint that reads a bearer credential says on every 401 what would have been
     * read. The descriptions of this package carry no double quote nor backslash and need no escaping.
     */
    public function challenge(): string
    {
        return sprintf('%s error="%s", error_description="%s"', self::SCHEME, $this->error, $this->errorDescription);
    }
}

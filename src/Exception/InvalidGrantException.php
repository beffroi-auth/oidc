<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * RFC 6749 §5.2 "invalid_grant": the authorization code or the refresh token is unknown, expired, used,
 * revoked, issued to another client, or does not match the redirect URI or the code verifier. One code
 * and one description for every one of these, so that the answer tells a guessing client nothing. The
 * token endpoint answers 400. For oidc_login, it is the one error meaning the refresh token is lost
 * (Symfony status RP-01).
 */
final class InvalidGrantException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('invalid_grant', $description, 400, false);
    }
}

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * RFC 8628 §3.5 "expired_token": the device code is past its lifetime and the client starts over. Told
 * apart from "invalid_grant" so that an appliance can show a new code rather than an error nobody can act
 * on; a code nobody ever issued is still "invalid_grant".
 */
final class ExpiredTokenException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('expired_token', $description, 400, false);
    }
}

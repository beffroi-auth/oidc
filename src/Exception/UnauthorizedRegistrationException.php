<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * The request presents nothing that authorises a registration on this tenant (RFC 7591 §1.2): no initial
 * access token where one is required, or one this provider will not act on.
 *
 * It reads the same whatever gave it away, a header that carries none, a value nobody was handed, a
 * token already worth nothing, one that expired or one the tenant took back: whoever does not hold a
 * token of this tenant learns nothing about the one they presented (decision 0006). That is one refusal,
 * so it is written once here and never beside each check.
 */
final class UnauthorizedRegistrationException extends UnauthorizedBearerRequestException
{
    public function __construct()
    {
        parent::__construct('The request does not carry an initial access token of this tenant (RFC 7591 section 1.2).');
    }
}

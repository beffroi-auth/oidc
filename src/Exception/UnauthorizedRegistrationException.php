<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * RFC 7591 §1.2
 */
final class UnauthorizedRegistrationException extends UnauthorizedBearerRequestException
{
    public function __construct()
    {
        parent::__construct('The request does not carry an initial access token of this tenant (RFC 7591 section 1.2).');
    }
}

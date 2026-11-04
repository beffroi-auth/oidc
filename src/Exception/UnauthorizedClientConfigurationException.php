<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * RFC 7592 §2.3
 */
final class UnauthorizedClientConfigurationException extends UnauthorizedBearerRequestException
{
    public function __construct()
    {
        parent::__construct('The request does not carry the registration access token of this client (RFC 7592 section 2.3).');
    }
}

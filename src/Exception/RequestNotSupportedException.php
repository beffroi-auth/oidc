<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * OIDC Core §3.1.2.6 "request_not_supported": the provider does not accept the "request" parameter
 * (request objects by value, OIDC Core §6.1), and says so in its metadata. Always sent back to the client:
 * the parameter is only looked at once the client and its redirect URI are known.
 */
final class RequestNotSupportedException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('request_not_supported', $description, 400, true);
    }
}

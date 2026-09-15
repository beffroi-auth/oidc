<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * OIDC Core §3.1.2.6 "request_uri_not_supported": the provider does not accept the "request_uri"
 * parameter (request objects by reference, OIDC Core §6.2), and never fetches one (decision 0006: no
 * outbound request on the client's word). Always sent back to the client.
 */
final class RequestUriNotSupportedException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('request_uri_not_supported', $description, 400, true);
    }
}

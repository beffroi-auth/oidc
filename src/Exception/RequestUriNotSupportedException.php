<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * OIDC Core §3.1.2.6 "request_uri_not_supported": no request object by reference (§6.2, decision 0006).
 */
final class RequestUriNotSupportedException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('request_uri_not_supported', $description, 400, true);
    }
}

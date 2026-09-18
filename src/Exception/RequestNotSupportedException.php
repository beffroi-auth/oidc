<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * OIDC Core §3.1.2.6 "request_not_supported": no request object by value (§6.1).
 */
final class RequestNotSupportedException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('request_not_supported', $description, 400, true);
    }
}

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use RuntimeException;

/**
 * RFC 6750 §3.1: the request carried no bearer token at all, whether it had no Authorization header, one
 * of another scheme, or no "access_token" form parameter. The resource answers 401 with the bare "Bearer"
 * challenge and no error code, so that a caller unaware of the scheme learns which one applies and
 * nothing else. It is not an OAuth 2.0 error: there is no "error" member to write.
 */
final class MissingBearerTokenException extends RuntimeException implements ExceptionInterface
{
    public const int STATUS_CODE = 401;

    public function __construct()
    {
        parent::__construct('The request carries no bearer token.');
    }
}

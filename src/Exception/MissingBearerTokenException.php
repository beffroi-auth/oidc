<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use RuntimeException;

/**
 * RFC 6750 §3.1: no bearer token at all; 401 with the bare "Bearer" challenge, no error code.
 */
final class MissingBearerTokenException extends RuntimeException implements ExceptionInterface
{
    public const int STATUS_CODE = 401;

    public function __construct()
    {
        parent::__construct('The request carries no bearer token.');
    }
}

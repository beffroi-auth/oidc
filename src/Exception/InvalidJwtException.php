<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use RuntimeException as BaseRuntimeException;

/**
 * A JWT a client sent cannot be read or does not verify: a client assertion (RFC 7523 §2.2) or a request
 * object (RFC 9101 §4). What the caller makes of it is its own: an authentication that fails, a request
 * that is refused. The message is for the audit trail and never reaches the client as it is.
 */
final class InvalidJwtException extends BaseRuntimeException implements ExceptionInterface
{
}

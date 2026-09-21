<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use RuntimeException as BaseRuntimeException;

/**
 * A client assertion could not be read or does not verify (RFC 7523 §3). Internal to the client
 * authentication: what the client reads back is "invalid_client" and nothing else (RFC 6749 §5.2), the
 * reason going to the audit trail alone.
 */
final class InvalidClientAssertionException extends BaseRuntimeException implements ExceptionInterface
{
}

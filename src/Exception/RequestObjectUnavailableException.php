<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use RuntimeException as BaseRuntimeException;

/**
 * The request object behind a "request_uri" could not be read back: the client answered an error,
 * answered too slowly, answered too much or redirected (decision 0006: no outbound redirect is
 * followed). The request is refused with "invalid_request_uri" and nothing else is touched; what
 * happened is in the audit trail.
 */
final class RequestObjectUnavailableException extends BaseRuntimeException implements ExceptionInterface
{
}

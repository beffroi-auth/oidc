<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use RuntimeException as BaseRuntimeException;

/**
 * Its message is for the audit trail and never reaches the client as it is.
 */
final class InvalidJwtException extends BaseRuntimeException implements ExceptionInterface
{
}

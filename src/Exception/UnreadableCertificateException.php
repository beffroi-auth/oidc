<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use RuntimeException as BaseRuntimeException;

/**
 * The presented certificate is not X.509, or a name registered for the client is not a distinguished name.
 */
final class UnreadableCertificateException extends BaseRuntimeException implements ExceptionInterface
{
}

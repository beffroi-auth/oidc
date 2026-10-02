<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use RuntimeException as BaseRuntimeException;

/**
 * The certificate a client presented could not be read: the bytes the edge handed over are not an X.509
 * certificate, or a name registered for a client is not a distinguished name. Nothing is guessed and the
 * authentication fails; what reached the provider is described in the audit trail and nowhere else.
 */
final class UnreadableCertificateException extends BaseRuntimeException implements ExceptionInterface
{
}

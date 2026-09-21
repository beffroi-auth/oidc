<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use RuntimeException as BaseRuntimeException;

/**
 * The keys a client publishes behind its "jwks_uri" could not be read back: the client answered an error,
 * answered too slowly, answered too much, redirected (decision 0006: no outbound redirect is followed) or
 * answered something that is not a JWK Set. The authentication fails and nothing else is touched.
 */
final class ClientKeysUnavailableException extends BaseRuntimeException implements ExceptionInterface
{
}

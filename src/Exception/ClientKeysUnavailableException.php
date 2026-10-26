<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use RuntimeException as BaseRuntimeException;

/**
 * The keys a client publishes could not be read back, or hold none of what is needed: behind its "jwks_uri"
 * the client answered an error, answered too slowly, answered too much, redirected (decision 0006: no
 * outbound redirect is followed) or answered something that is not a JWK Set; or it publishes no key, or
 * none a document it asked to be encrypted can be addressed to. The method that was authenticating it
 * fails, a document addressed to it does not leave, and nothing else is touched: the token endpoint reads
 * the key of an ID token before the grant spends anything.
 */
final class ClientKeysUnavailableException extends BaseRuntimeException implements ExceptionInterface
{
}

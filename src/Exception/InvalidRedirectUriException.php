<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use Throwable;

/**
 * RFC 7591 §3.2.2 "invalid_redirect_uri": one of the redirection URIs of the registration is invalid, or the
 * registration carries none where the grants it names need one. A fragment, credentials, a scheme of its own
 * and plain HTTP on a name are all a redirection URI that is not one.
 */
final class InvalidRedirectUriException extends UnreadableClientMetadataException
{
    public function __construct(?string $member, ?string $source, string $message, ?Throwable $previous = null)
    {
        parent::__construct('invalid_redirect_uri', $member, $source, $message, $previous);
    }
}

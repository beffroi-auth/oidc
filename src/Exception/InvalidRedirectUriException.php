<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Throwable;

/**
 * RFC 7591 §3.2.2
 */
final class InvalidRedirectUriException extends UnreadableClientMetadataException
{
    public function __construct(?string $member, ?string $source, string $message, ?Throwable $previous = null)
    {
        parent::__construct('invalid_redirect_uri', $member, $source, $message, $previous);
    }
}

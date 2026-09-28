<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use Throwable;

/**
 * RFC 7591 §3.2.2 "invalid_client_metadata": the value of one of the members of the registration is invalid,
 * or two of them contradict each other. Every member but the redirection URIs answers with this.
 */
final class InvalidClientMetadataException extends UnreadableClientMetadataException
{
    public function __construct(?string $member, ?string $source, string $message, ?Throwable $previous = null)
    {
        parent::__construct('invalid_client_metadata', $member, $source, $message, $previous);
    }
}

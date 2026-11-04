<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Throwable;

/**
 * RFC 6749 §5.2
 *
 * One description whatever the cause, so that a guessing client learns nothing.
 */
final class InvalidGrantException extends OAuth2Exception
{
    public function __construct(string $description, ?Throwable $previous = null)
    {
        parent::__construct('invalid_grant', $description, 400, false, $previous);
    }
}

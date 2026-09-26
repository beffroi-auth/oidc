<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use Throwable;

/**
 * RFC 6749 §5.2 "invalid_grant": one description whatever the cause, so that a guessing client learns nothing.
 * What went wrong is carried as the cause, which the audit trail of the provider reads and no response does.
 */
final class InvalidGrantException extends OAuth2Exception
{
    public function __construct(string $description, ?Throwable $previous = null)
    {
        parent::__construct('invalid_grant', $description, 400, false, $previous);
    }
}

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * RFC 6749 §5.2 "invalid_grant": one description whatever the cause, so that a guessing client learns nothing.
 */
final class InvalidGrantException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('invalid_grant', $description, 400, false);
    }
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * RFC 6749 §5.2 "unsupported_grant_type" (decision 0006).
 */
final class UnsupportedGrantTypeException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('unsupported_grant_type', $description, 400, false);
    }
}

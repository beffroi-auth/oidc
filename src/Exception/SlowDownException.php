<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * RFC 8628 §3.5
 */
final class SlowDownException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('slow_down', $description, 400, false);
    }
}

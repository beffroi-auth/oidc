<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * RFC 8628 §3.5 "slow_down": the same answer as "authorization_pending", for a client that polled sooner
 * than the interval it was given. It is told to add five seconds to that interval, for this request and
 * every one after it.
 */
final class SlowDownException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('slow_down', $description, 400, false);
    }
}

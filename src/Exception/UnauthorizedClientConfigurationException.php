<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * The request presents nothing that reads this client (RFC 7592 §2.3): no registration access token where
 * one is required, or one this provider will not act on.
 *
 * It reads the same whatever gave it away, a header that carries none, a value nobody was handed, a token
 * drawn for another client, or a client that no longer exists: §2.3 requires that a token belonging to
 * another client be refused, and a caller that does not hold the token of a client of this tenant learns
 * nothing about the one it presented, not even whether that client exists (decision 0006). That is one
 * refusal, so it is written once here and never beside each check.
 */
final class UnauthorizedClientConfigurationException extends UnauthorizedBearerRequestException
{
    public function __construct()
    {
        parent::__construct('The request does not carry the registration access token of this client (RFC 7592 section 2.3).');
    }
}

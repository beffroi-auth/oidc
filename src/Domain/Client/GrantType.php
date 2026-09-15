<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

/**
 * The grants a client may use at the token endpoint (RFC 7591 §2 "grant_types"). Only the two of the
 * authorization code flow exist: no implicit, no password, no client credentials (decision 0006).
 */
enum GrantType: string
{
    case AuthorizationCode = 'authorization_code';
    case RefreshToken = 'refresh_token';
}

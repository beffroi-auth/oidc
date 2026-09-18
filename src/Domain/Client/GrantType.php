<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

/**
 * RFC 7591 §2 "grant_types": the two of the authorization code flow, nothing else (decision 0006).
 */
enum GrantType: string
{
    case AuthorizationCode = 'authorization_code';
    case RefreshToken = 'refresh_token';
}

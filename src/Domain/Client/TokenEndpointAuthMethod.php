<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

/**
 * How a client authenticates at the token endpoint (RFC 6749 §2.3.1, names from OIDC Core §9); exactly one
 * per client.
 */
enum TokenEndpointAuthMethod: string
{
    case ClientSecretBasic = 'client_secret_basic';
    case ClientSecretPost = 'client_secret_post';
    case None = 'none';

    /**
     * "none" is a public client (RFC 6749 §2.1).
     */
    public function usesSecret(): bool
    {
        return $this !== self::None;
    }
}

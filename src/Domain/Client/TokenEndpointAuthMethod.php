<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

/**
 * How a client authenticates at the token endpoint (RFC 6749 §2.3.1, names from OIDC Core §9). A client is
 * registered with exactly one; presenting another one is refused. The assertion methods (private_key_jwt,
 * client_secret_jwt) are behind a port to come, not a case to add here.
 */
enum TokenEndpointAuthMethod: string
{
    case ClientSecretBasic = 'client_secret_basic';
    case ClientSecretPost = 'client_secret_post';
    case None = 'none';

    /**
     * Whether the method proves possession of a client secret. A client using "none" is a public client
     * (RFC 6749 §2.1): nothing but PKCE binds its authorization codes to it.
     */
    public function usesSecret(): bool
    {
        return $this !== self::None;
    }
}

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * RFC 6749 §5.2 "invalid_client": unknown client, no client authentication, an unsupported or unexpected
 * method, or a wrong secret. Always 401 here (architecture §4.10). When the client tried the Authorization
 * header, the response carries the WWW-Authenticate challenge RFC 6749 §5.2 requires, with the scheme the
 * provider supports (RFC 7617 §2). It never reaches a redirect URI: the token endpoint does not redirect.
 */
final class InvalidClientException extends OAuth2Exception
{
    /**
     * @param string|null $challenge the value of the WWW-Authenticate header, when the client used the Authorization header
     */
    public function __construct(
        string $description,
        public readonly ?string $challenge = null,
    ) {
        parent::__construct('invalid_client', $description, 401, false);
    }
}

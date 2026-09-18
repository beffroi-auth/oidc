<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * RFC 6749 §5.2 "invalid_client": always 401 (architecture §4.10), with the WWW-Authenticate challenge
 * when the client tried the Authorization header.
 */
final class InvalidClientException extends OAuth2Exception
{
    /**
     * @param string|null $challenge the WWW-Authenticate header, when the client used the Authorization header
     */
    public function __construct(
        string $description,
        public readonly ?string $challenge = null,
    ) {
        parent::__construct('invalid_client', $description, 401, false);
    }
}

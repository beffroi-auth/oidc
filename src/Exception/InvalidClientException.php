<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * RFC 6749 §5.2
 */
final class InvalidClientException extends OAuth2Exception
{
    public function __construct(
        string $description,
        public readonly ?string $challenge = null,
    ) {
        parent::__construct('invalid_client', $description, 401, false);
    }
}

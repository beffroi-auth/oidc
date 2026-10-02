<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * RFC 7009 §2.2.1 "unsupported_token_type": a token the provider has no way to revoke (architecture §4.6).
 */
final class UnsupportedTokenTypeException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('unsupported_token_type', $description, 400, false);
    }
}

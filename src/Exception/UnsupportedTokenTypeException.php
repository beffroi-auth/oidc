<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

/**
 * RFC 7009 §2.2.1 "unsupported_token_type": the revocation endpoint was handed a token of this provider
 * that it has no way to revoke, a self-contained access token, which lives in nobody's store and expires
 * on its own (architecture §4.6). Answered 400, never a redirect.
 */
final class UnsupportedTokenTypeException extends OAuth2Exception
{
    public function __construct(string $description)
    {
        parent::__construct('unsupported_token_type', $description, 400, false);
    }
}

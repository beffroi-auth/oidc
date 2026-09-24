<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use Heidi\Oidc\Domain\Scope\Scopes;

/**
 * RFC 6750 §3.1 "insufficient_scope": 403, the challenge naming the scopes that would have sufficed.
 */
final class InsufficientScopeException extends OAuth2Exception
{
    public function __construct(
        string $description,
        public readonly Scopes $scopes,
    ) {
        parent::__construct('insufficient_scope', $description, 403, false);
    }
}

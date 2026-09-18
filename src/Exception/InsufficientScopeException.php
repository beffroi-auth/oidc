<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use Heidi\Oidc\Domain\Scope\Scope;

/**
 * RFC 6750 §3.1 "insufficient_scope": 403, the challenge naming the scopes that would have sufficed.
 */
final class InsufficientScopeException extends OAuth2Exception
{
    /**
     * @var non-empty-list<Scope>
     */
    public readonly array $scopes;

    /**
     * @param list<Scope> $scopes at least one
     */
    public function __construct(string $description, array $scopes)
    {
        if ($scopes === []) {
            throw new InvalidArgumentException('An insufficient_scope error names the scopes that were required (RFC 6750 section 3).');
        }
        $this->scopes = $scopes;
        parent::__construct('insufficient_scope', $description, 403, false);
    }
}

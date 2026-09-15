<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use Heidi\Oidc\Domain\Scope\Scope;

/**
 * RFC 6750 §3.1 "insufficient_scope": the bearer token is valid but does not carry a scope the resource
 * requires; 403, and the challenge names the scopes that would have sufficed, so that the client can ask
 * for them. Never a redirect: only a protected resource raises it.
 */
final class InsufficientScopeException extends OAuth2Exception
{
    /**
     * @var non-empty-list<Scope>
     */
    public readonly array $scopes;

    /**
     * @param list<Scope> $scopes the scopes necessary to access the resource, at least one
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

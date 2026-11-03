<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Beffroi\Oidc\Domain\Scope\Scopes;

/**
 * RFC 6750 §3.1 "insufficient_scope": 403, the challenge naming the scopes that would have sufficed, under
 * the scheme the token was presented under (RFC 9449 §7.2).
 */
final class InsufficientScopeException extends OAuth2Exception implements ChallengeInterface
{
    /**
     * @param non-empty-string $scheme the scheme the token was presented under, spelled as this provider spells it
     */
    public function __construct(
        string $description,
        public readonly Scopes $scopes,
        private readonly string $scheme,
    ) {
        parent::__construct('insufficient_scope', $description, 403, false);
    }

    public function challengeScheme(): string
    {
        return $this->scheme;
    }

    public function challengeHeaders(): array
    {
        return [];
    }
}

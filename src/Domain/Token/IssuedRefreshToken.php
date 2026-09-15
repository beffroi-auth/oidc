<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use Heidi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;

/**
 * A refresh token at the one moment both sides of it exist: the record the provider keeps and the value
 * the client is about to receive. The value goes into the response and nowhere else.
 */
final readonly class IssuedRefreshToken
{
    public function __construct(
        public RefreshToken $token,
        #[SensitiveParameter]
        public string $value,
    ) {
        if (RefreshToken::hash($value) !== $token->tokenHash) {
            throw new InvalidArgumentException('The refresh token record is the hash of the value.');
        }
    }
}

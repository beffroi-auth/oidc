<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use Heidi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;

/**
 * A refresh token at the one moment both its record and its value exist.
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

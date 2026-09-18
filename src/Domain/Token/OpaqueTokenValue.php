<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use function hash;
use function random_bytes;
use SensitiveParameter;

/**
 * The value of an opaque token (architecture §4.6): 256 bits in base64url, no dot, kept as its hex SHA-256.
 */
final readonly class OpaqueTokenValue
{
    public static function draw(): string
    {
        return Base64Url::encode(random_bytes(32));
    }

    public static function hash(#[SensitiveParameter] string $value): string
    {
        return hash('sha256', $value);
    }
}

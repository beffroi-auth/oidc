<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use function hash;
use function random_bytes;
use SensitiveParameter;

/**
 * The value of an opaque token and how a store names it (architecture §4.6): 256 bits from the CSPRNG,
 * base64url without padding (43 characters, no dot, which is how it is told from a compact JWS at a
 * glance), kept and looked up as its hex SHA-256, so that a leaked table of tokens yields nothing usable.
 * The repositories draw and hash, the rest of the module never sees a hash.
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

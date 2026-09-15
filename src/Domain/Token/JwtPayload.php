<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use function json_encode;
use const JSON_PRESERVE_ZERO_FRACTION;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;

/**
 * How a claims set becomes the payload of a JWT (RFC 7519 §3): one JSON object, UTF-8 as it is, slashes
 * as they are, a float kept a float. A claim that cannot be encoded is a programming error, not a
 * response.
 */
final readonly class JwtPayload
{
    /**
     * @param array<string, mixed> $claims
     */
    public static function encode(array $claims): string
    {
        // an empty claims set is still an object, which json_encode() would write as a list
        if ($claims === []) {
            return '{}';
        }

        return json_encode($claims, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
    }
}

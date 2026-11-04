<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use function json_encode;
use const JSON_PRESERVE_ZERO_FRACTION;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;

/**
 * RFC 7519 §3
 */
final readonly class JwtPayload
{
    /**
     * An empty claims set is "{}", which json_encode() would write as "[]".
     *
     * @param array<string, mixed> $claims
     */
    public static function encode(array $claims): string
    {
        if ($claims === []) {
            return '{}';
        }

        return json_encode($claims, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
    }
}

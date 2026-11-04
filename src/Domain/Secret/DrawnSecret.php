<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Secret;

use function hash;
use function preg_match;
use SensitiveParameter;

/**
 * A store keeps its SHA-256 and never the value, so that whoever reads the store has nothing to present.
 */
final readonly class DrawnSecret
{
    public const string PATTERN = '/^[A-Za-z0-9_-]{43}$/D';

    public const string DIGEST_PATTERN = '/^[0-9a-f]{64}$/D';

    /**
     * Random bytes drawn, before base64url encoding.
     */
    public const int LENGTH = 32;

    public static function digestOf(#[SensitiveParameter] string $value): string
    {
        return hash('sha256', $value);
    }

    public static function isDigest(string $digest): bool
    {
        return preg_match(self::DIGEST_PATTERN, $digest) === 1;
    }

    public static function isValue(#[SensitiveParameter] string $value): bool
    {
        return preg_match(self::PATTERN, $value) === 1;
    }
}

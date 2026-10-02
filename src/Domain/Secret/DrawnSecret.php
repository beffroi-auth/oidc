<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Secret;

use function hash;
use function preg_match;
use SensitiveParameter;

/**
 * A value this provider draws for one holder and recognises again later: an authorization code, a
 * refresh token, an opaque access token, the reference a pushed request answers with, the identifier of
 * an interaction. All of them are the same thing, so all of them are drawn the same way and kept the
 * same way, and none of them writes it again.
 *
 * 256 bits (RFC 9126 §7.1 asks for at least 128), base64url without padding, which is what makes the
 * value safe in a URL and in a form. What the provider keeps of it is the hex SHA-256 and never the
 * value, so that a store read by someone else replays nothing: whoever holds the store holds digests of
 * secrets they cannot present.
 *
 * This is the shape and nothing else: what it is made of and what a store keeps of it. Drawing one is
 * SecretDrawer, which is given its randomness as a use case is given its clock.
 */
final readonly class DrawnSecret
{
    /**
     * The shape of a value drawn here: 256 bits in base64url is 43 characters and no padding.
     */
    public const string PATTERN = '/^[A-Za-z0-9_-]{43}$/D';

    /**
     * The shape of what is kept instead of the value: a SHA-256 in lowercase hexadecimal.
     */
    public const string DIGEST_PATTERN = '/^[0-9a-f]{64}$/D';

    /**
     * How many bytes are drawn for one, before they are written in base64url.
     */
    public const int LENGTH = 32;

    /**
     * What a store keeps of a value, and what a lookup is made by.
     */
    public static function digestOf(#[SensitiveParameter] string $value): string
    {
        return hash('sha256', $value);
    }

    /**
     * Whether a string is a digest of one of these, which is what every record holding one checks of
     * itself rather than trusting what it was handed.
     */
    public static function isDigest(string $digest): bool
    {
        return preg_match(self::DIGEST_PATTERN, $digest) === 1;
    }

    public static function isValue(#[SensitiveParameter] string $value): bool
    {
        return preg_match(self::PATTERN, $value) === 1;
    }
}

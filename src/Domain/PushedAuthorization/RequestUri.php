<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\PushedAuthorization;

use Heidi\Oidc\Domain\Secret\DrawnSecret;
use function preg_match;
use SensitiveParameter;

/**
 * The reference the pushed authorization request endpoint answers with (RFC 9126 §2.2): the URN of
 * RFC 9101 §5.2.1, with 256 bits of randomness behind the prefix, which is the entropy RFC 9126 §7.1
 * asks for. The provider keeps its SHA-256 and never the value, as it keeps an authorization code, so
 * that a store read by someone else replays nothing.
 */
final readonly class RequestUri
{
    /**
     * RFC 9126 §2.2: the form the specification registers and the one the authorization endpoint
     * recognises as one of ours.
     */
    public const string URN_PREFIX = 'urn:ietf:params:oauth:request_uri:';

    private const string PATTERN = '/^urn:ietf:params:oauth:request_uri:[A-Za-z0-9_-]{43}$/D';

    private function __construct(
        public string $value,
    ) {
    }

    /**
     * 256 bits, base64url without padding, behind the prefix.
     */
    public static function generate(): self
    {
        return new self(self::URN_PREFIX . DrawnSecret::draw());
    }

    /**
     * Whether a value claims to be one this provider issued, which is what tells a pushed request from
     * the request object by reference of OIDC Core §6.2: what is not ours is left to the authorization
     * endpoint to answer for, and is never fetched over the network.
     */
    public static function isOurs(#[SensitiveParameter] string $value): bool
    {
        return preg_match(self::PATTERN, $value) === 1;
    }

    public static function hashOf(#[SensitiveParameter] string $value): string
    {
        return DrawnSecret::digestOf($value);
    }

    public function hash(): string
    {
        return self::hashOf($this->value);
    }
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\PushedAuthorization;

use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function preg_match;
use SensitiveParameter;

/**
 * RFC 9126 §2.2
 */
final readonly class RequestUri
{
    /**
     * RFC 9126 §2.2
     */
    public const string URN_PREFIX = 'urn:ietf:params:oauth:request_uri:';

    private const string PATTERN = '/^urn:ietf:params:oauth:request_uri:[A-Za-z0-9_-]{43}$/D';

    private function __construct(
        public string $value,
    ) {
    }

    /**
     * @throws InvalidArgumentException
     */
    public static function of(#[SensitiveParameter] string $drawn): self
    {
        if (! DrawnSecret::isValue($drawn)) {
            throw new InvalidArgumentException('A request URI carries a value of the shape this provider draws.');
        }

        return new self(self::URN_PREFIX . $drawn);
    }

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

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Exchange;

use Beffroi\Oidc\Exception\InvalidArgumentException;
use function preg_match;
use function sprintf;
use Stringable;

/**
 * RFC 8693 §3
 */
final readonly class TokenTypeIdentifier implements Stringable
{
    public const string ACCESS_TOKEN = 'urn:ietf:params:oauth:token-type:access_token';

    /**
     * RFC 3986 §3, no fragment
     */
    private const string PATTERN = '/^[A-Za-z][A-Za-z0-9+.-]*:[^\s#]+$/D';

    public function __construct(
        public string $value,
    ) {
        if (preg_match(self::PATTERN, $value) !== 1) {
            throw new InvalidArgumentException(sprintf(
                'The token type identifier "%s" must be an absolute URI without a fragment (RFC 8693 section 3).',
                $value,
            ));
        }
    }

    public static function accessToken(): self
    {
        return new self(self::ACCESS_TOKEN);
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }

    public function __toString(): string
    {
        return $this->value;
    }
}

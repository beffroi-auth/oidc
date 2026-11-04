<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Resource;

use Beffroi\Oidc\Exception\InvalidArgumentException;
use function preg_match;
use function sprintf;
use function str_contains;
use Stringable;

/**
 * RFC 8707 §2
 */
final readonly class ResourceIndicator implements Stringable
{
    /**
     * RFC 3986 §3.1
     */
    private const string PATTERN = '/^[A-Za-z][A-Za-z0-9+.\-]*:[\x21-\x7E]+$/D';

    /**
     * @throws InvalidArgumentException
     */
    public function __construct(
        public string $value,
    ) {
        if (str_contains($value, '#')) {
            throw new InvalidArgumentException(sprintf('The resource "%s" must not carry a fragment component (RFC 8707 section 2).', $value));
        }
        if (preg_match(self::PATTERN, $value) !== 1) {
            throw new InvalidArgumentException(sprintf('The resource "%s" is not an absolute URI (RFC 8707 section 2, RFC 3986 section 4.3).', $value));
        }
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

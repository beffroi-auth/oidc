<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Scope;

use Heidi\Oidc\Exception\InvalidArgumentException;
use function preg_match;
use function sprintf;
use Stringable;

/**
 * One scope token (RFC 6749 §3.3), compared byte for byte.
 */
final readonly class Scope implements Stringable
{
    private const string PATTERN = '/^[\x21\x23-\x5B\x5D-\x7E]+$/';

    public function __construct(
        public string $value,
    ) {
        if (preg_match(self::PATTERN, $value) !== 1) {
            throw new InvalidArgumentException(sprintf('"%s" is not a scope token (RFC 6749 §3.3).', $value));
        }
    }

    public static function openid(): self
    {
        return new self('openid');
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

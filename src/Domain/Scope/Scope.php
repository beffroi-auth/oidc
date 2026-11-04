<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Scope;

use function array_any;
use function explode;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function preg_match;
use function sprintf;
use Stringable;

/**
 * RFC 6749 §3.3
 */
final readonly class Scope implements Stringable
{
    private const string PATTERN = '/^[\x21\x23-\x5B\x5D-\x7E]+$/D';

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

    /**
     * OIDC Core §11
     */
    public static function offlineAccess(): self
    {
        return new self('offline_access');
    }

    /**
     * RFC 6749 §3.3, RFC 8693 §4.2
     *
     * @throws InvalidArgumentException
     * @return non-empty-list<self> each once, in the order first seen
     */
    public static function parseList(string $scope): array
    {
        $scopes = [];
        foreach (explode(' ', $scope) as $token) {
            $candidate = new self($token);
            if (! array_any($scopes, static fn (self $kept): bool => $kept->equals($candidate))) {
                $scopes[] = $candidate;
            }
        }

        /** @var non-empty-list<self> $scopes */
        return $scopes;
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

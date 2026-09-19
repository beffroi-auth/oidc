<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Scope;

use function array_any;
use function explode;
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

    /**
     * A "scope" parameter or claim (RFC 6749 §3.3, RFC 8693 §4.2): space-delimited tokens, a set, so a token
     * repeated counts once, in the order first seen. Written once here, whoever reads it: the authorization
     * request, the refresh token grant, the access token verifier.
     *
     * @throws InvalidArgumentException when a token is not one, the empty string included
     * @return non-empty-list<self>
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

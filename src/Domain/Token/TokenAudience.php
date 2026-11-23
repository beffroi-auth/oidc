<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use function array_is_list;
use function array_unique;
use function array_values;
use ArrayIterator;
use function count;
use Countable;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function in_array;
use function is_array;
use function is_string;
use IteratorAggregate;
use Traversable;

/**
 * RFC 7519 §4.1.3
 *
 * @implements IteratorAggregate<int, string>
 */
final readonly class TokenAudience implements Countable, IteratorAggregate
{
    /**
     * @var non-empty-list<string> in the order they were first seen
     */
    public array $values;

    /**
     * @param list<string> $values at least one; a duplicate counts once
     *
     * @throws InvalidArgumentException
     */
    public function __construct(array $values)
    {
        foreach ($values as $value) {
            if ($value === '') {
                throw new InvalidArgumentException('An audience names something (RFC 7519 section 4.1.3).');
            }
        }
        if ($values === []) {
            throw new InvalidArgumentException('An access token is addressed to at least one audience (RFC 7519 section 4.1.3).');
        }
        $this->values = array_values(array_unique($values));
    }

    /**
     * RFC 8707 §2
     *
     * Never defaulted to the resources the client registered: a token valid at several resources is valid at each of
     * them (RFC 8707 §3).
     */
    public static function of(Client $client, ?ResourceIndicators $resources): self
    {
        return $resources === null ? new self([$client->registration->clientId]) : new self($resources->values());
    }

    /**
     * RFC 7519 §4.1.3
     *
     * @throws InvalidArgumentException
     */
    public static function fromClaim(mixed $aud): self
    {
        if (is_string($aud)) {
            return new self([$aud]);
        }
        if (! is_array($aud) || ! array_is_list($aud)) {
            throw new InvalidArgumentException('An "aud" claim is a string or a list of strings (RFC 7519 section 4.1.3).');
        }
        foreach ($aud as $value) {
            if (! is_string($value)) {
                throw new InvalidArgumentException('An "aud" claim is a string or a list of strings (RFC 7519 section 4.1.3).');
            }
        }

        return new self($aud);
    }

    /**
     * RFC 7519 §4.1.3
     *
     * @return string|non-empty-list<string>
     */
    public function claim(): string|array
    {
        return count($this->values) === 1 ? $this->values[0] : $this->values;
    }

    public function has(string $value): bool
    {
        return in_array($value, $this->values, true);
    }

    public function equals(self $other): bool
    {
        return $this->values === $other->values;
    }

    public function count(): int
    {
        return count($this->values);
    }

    /**
     * @return Traversable<int, string>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->values);
    }
}

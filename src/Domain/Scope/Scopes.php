<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Scope;

use function array_all;
use function array_any;
use function array_map;
use function count;
use ArrayIterator;
use Countable;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function implode;
use IteratorAggregate;
use Stringable;
use Traversable;

/**
 * RFC 6749 §3.3
 *
 * @implements IteratorAggregate<int, Scope>
 */
final readonly class Scopes implements Countable, IteratorAggregate, Stringable
{
    /**
     * @var non-empty-list<Scope> in the order they were first seen
     */
    public array $all;

    /**
     * @param list<Scope> $scopes at least one; a duplicate counts once
     *
     * @throws InvalidArgumentException
     */
    public function __construct(array $scopes)
    {
        $kept = [];
        foreach ($scopes as $scope) {
            if (! array_any($kept, static fn (Scope $seen): bool => $seen->equals($scope))) {
                $kept[] = $scope;
            }
        }
        if ($kept === []) {
            throw new InvalidArgumentException('A set of scopes holds at least one scope (RFC 6749 section 3.3).');
        }
        $this->all = $kept;
    }

    /**
     * @throws InvalidArgumentException
     */
    public static function parse(string $scope): self
    {
        return new self(Scope::parseList($scope));
    }

    public function has(Scope $scope): bool
    {
        return array_any($this->all, static fn (Scope $held): bool => $held->equals($scope));
    }

    public function covers(self $scopes): bool
    {
        return array_all($scopes->all, fn (Scope $scope): bool => $this->has($scope));
    }

    /**
     * @return non-empty-list<string>
     */
    public function values(): array
    {
        return array_map(static fn (Scope $scope): string => $scope->value, $this->all);
    }

    public function equals(self $other): bool
    {
        return $this->covers($other) && $other->covers($this);
    }

    public function count(): int
    {
        return count($this->all);
    }

    /**
     * @return Traversable<int, Scope>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->all);
    }

    /**
     * RFC 6749 §3.3
     */
    public function __toString(): string
    {
        return implode(' ', $this->all);
    }
}

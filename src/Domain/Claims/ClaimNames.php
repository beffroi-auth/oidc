<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Claims;

use function array_filter;
use function array_is_list;
use function array_values;
use ArrayIterator;
use Countable;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function count;
use function in_array;
use function is_string;
use IteratorAggregate;
use Traversable;

/**
 * @implements IteratorAggregate<int, string>
 */
final readonly class ClaimNames implements Countable, IteratorAggregate
{
    /**
     * @var list<string>
     */
    public array $all;

    /**
     * @param list<string> $names
     *
     * @throws InvalidArgumentException when a name is empty
     */
    public function __construct(array $names = [])
    {
        $kept = [];
        foreach ($names as $name) {
            if ($name === '') {
                throw new InvalidArgumentException('A claim has a name (OIDC Core section 5.1).');
            }
            if (! in_array($name, $kept, true)) {
                $kept[] = $name;
            }
        }
        $this->all = $kept;
    }

    public function has(string $name): bool
    {
        return in_array($name, $this->all, true);
    }

    public function covers(self $other): bool
    {
        return $other->without($this)->isEmpty();
    }

    public function with(self $other): self
    {
        return new self([...$this->all, ...$other->all]);
    }

    public function within(self $other): self
    {
        return new self(array_values(array_filter($this->all, $other->has(...))));
    }

    public function without(self $other): self
    {
        return new self(array_values(array_filter($this->all, static fn (string $name): bool => ! $other->has($name))));
    }

    public function isEmpty(): bool
    {
        return $this->all === [];
    }

    public function count(): int
    {
        return count($this->all);
    }

    /**
     * @return Traversable<int, string>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->all);
    }

    /**
     * @return list<string>
     */
    public function toDocument(): array
    {
        return $this->all;
    }

    /**
     * @param array<array-key, mixed> $document
     *
     * @throws InvalidArgumentException
     */
    public static function fromDocument(array $document): self
    {
        if (! array_is_list($document)) {
            throw new InvalidArgumentException('A set of claims is a list of their names (OIDC Core section 5.1).');
        }
        $names = [];
        foreach ($document as $name) {
            if (! is_string($name)) {
                throw new InvalidArgumentException('A set of claims holds their names (OIDC Core section 5.1).');
            }
            $names[] = $name;
        }

        return new self($names);
    }
}

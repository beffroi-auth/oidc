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
 * Claims by their names (OIDC Core §5.1): each named once, in the order it was first seen, and none at all
 * being a set too. What a request asks for one by one (§5.5), what a scope stands for (§5.4) and what a
 * consent holds by name are each one of these, so that what a set answers is answered once: whether it
 * holds a name, whether it covers another set, and what two sets hold together, in common or apart.
 *
 * @implements IteratorAggregate<int, string>
 */
final readonly class ClaimNames implements Countable, IteratorAggregate
{
    /**
     * @var list<string> in the order they were first seen
     */
    public array $all;

    /**
     * @param list<string> $names a name given twice counts once
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

    /**
     * Every name of the other set is held here.
     */
    public function covers(self $other): bool
    {
        return $other->without($this)->isEmpty();
    }

    /**
     * Both sets as one, the names held here first.
     */
    public function with(self $other): self
    {
        return new self([...$this->all, ...$other->all]);
    }

    /**
     * The names held here that the other set holds too, in the order they are held here.
     */
    public function within(self $other): self
    {
        return new self(array_values(array_filter($this->all, $other->has(...))));
    }

    /**
     * The names held here that the other set does not hold, in the order they are held here.
     */
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
     * A set is walked over as a set: what a page listing them does.
     *
     * @return Traversable<int, string>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->all);
    }

    /**
     * The document a column holds it as: a JSON list, the names being a set in an order and nothing being
     * keyed by them. A set that holds no name writes an empty list, which is what that value is.
     *
     * @return list<string>
     */
    public function toDocument(): array
    {
        return $this->all;
    }

    /**
     * @param array<array-key, mixed> $document
     *
     * @throws InvalidArgumentException when the document is not a list, or holds something that is not a claim name
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

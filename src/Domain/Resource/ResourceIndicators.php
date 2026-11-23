<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Resource;

use function array_all;
use function array_any;
use function array_flip;
use function array_map;
use function array_values;
use ArrayIterator;
use function count;
use Countable;
use function explode;
use function implode;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use IteratorAggregate;
use Traversable;

/**
 * RFC 8707 §2
 *
 * @implements IteratorAggregate<int, ResourceIndicator>
 */
final readonly class ResourceIndicators implements Countable, IteratorAggregate
{
    private const string SEPARATOR = ' ';

    /**
     * @var non-empty-list<ResourceIndicator> in the order they were first seen
     */
    public array $all;

    /**
     * @param list<ResourceIndicator> $resources at least one; a duplicate counts once
     *
     * @throws InvalidArgumentException
     */
    public function __construct(array $resources)
    {
        $kept = [];
        foreach ($resources as $resource) {
            $kept[$resource->value] ??= $resource;
        }
        if ($kept === []) {
            throw new InvalidArgumentException('A set of resources holds at least one resource (RFC 8707 section 2).');
        }
        $this->all = array_values($kept);
    }

    /**
     * @param list<string> $values
     *
     * @throws InvalidArgumentException
     */
    public static function of(array $values): self
    {
        return new self(array_map(static fn (string $value): ResourceIndicator => new ResourceIndicator($value), $values));
    }

    public function has(ResourceIndicator $resource): bool
    {
        return array_any($this->all, static fn (ResourceIndicator $held): bool => $held->equals($resource));
    }

    public function covers(self $resources): bool
    {
        $held = array_flip($this->values());

        return array_all($resources->all, static fn (ResourceIndicator $resource): bool => isset($held[$resource->value]));
    }

    /**
     * @return non-empty-list<string>
     */
    public function values(): array
    {
        return array_map(static fn (ResourceIndicator $resource): string => $resource->value, $this->all);
    }

    /**
     * Space delimited: a resource indicator carries no space.
     */
    public function toDocument(): string
    {
        return implode(self::SEPARATOR, $this->values());
    }

    /**
     * @throws InvalidArgumentException
     */
    public static function fromDocument(string $document): self
    {
        return self::of(explode(self::SEPARATOR, $document));
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
     * @return Traversable<int, ResourceIndicator>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->all);
    }
}

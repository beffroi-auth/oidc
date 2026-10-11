<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Resource;

use function array_all;
use function array_any;
use function array_map;
use ArrayIterator;
use function count;
use Countable;
use function explode;
use function implode;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use IteratorAggregate;
use Traversable;

/**
 * The resources a request names (RFC 8707 §2): at least one, each named once, in the order it was first
 * seen. Everything that carries resources holds one of these, so that what a set answers is answered
 * once: whether it holds a resource, and whether it covers another set.
 *
 * At least one, because a request that names no resource carries no set at all: the absence is a null
 * and never an empty set, exactly as it is for the scopes of a token.
 *
 * @implements IteratorAggregate<int, ResourceIndicator>
 */
final readonly class ResourceIndicators implements Countable, IteratorAggregate
{
    /**
     * What delimits two resources where a column holds the set, as a space delimits two scopes on the
     * wire (RFC 6749 §3.3).
     */
    private const string SEPARATOR = ' ';

    /**
     * @var non-empty-list<ResourceIndicator> in the order they were first seen
     */
    public array $all;

    /**
     * @param list<ResourceIndicator> $resources at least one; a resource named twice counts once
     *
     * @throws InvalidArgumentException when the set is empty
     */
    public function __construct(array $resources)
    {
        $kept = [];
        foreach ($resources as $resource) {
            if (! array_any($kept, static fn (ResourceIndicator $seen): bool => $seen->equals($resource))) {
                $kept[] = $resource;
            }
        }
        if ($kept === []) {
            throw new InvalidArgumentException('A set of resources holds at least one resource (RFC 8707 section 2).');
        }
        $this->all = $kept;
    }

    /**
     * The values of a "resource" parameter, as the request carried them.
     *
     * @param list<string> $values
     *
     * @throws InvalidArgumentException when a value is not an absolute URI, or when there is none
     */
    public static function of(array $values): self
    {
        return new self(array_map(static fn (string $value): ResourceIndicator => new ResourceIndicator($value), $values));
    }

    public function has(ResourceIndicator $resource): bool
    {
        return array_any($this->all, static fn (ResourceIndicator $held): bool => $held->equals($resource));
    }

    /**
     * Every resource of the other set is held here: what a grant has to cover for the resources a token
     * request names (RFC 8707 §2.2).
     */
    public function covers(self $resources): bool
    {
        return array_all($resources->all, fn (ResourceIndicator $resource): bool => $this->has($resource));
    }

    /**
     * @return non-empty-list<string>
     */
    public function values(): array
    {
        return array_map(static fn (ResourceIndicator $resource): string => $resource->value, $this->all);
    }

    /**
     * The value a column holds a set of resources as, space delimited: a resource indicator is an
     * absolute URI and carries no space, so the set writes itself and reads itself back exactly as a set
     * of scopes does.
     */
    public function toDocument(): string
    {
        return implode(self::SEPARATOR, $this->values());
    }

    /**
     * @throws InvalidArgumentException when a value is not an absolute URI, or when there is none
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

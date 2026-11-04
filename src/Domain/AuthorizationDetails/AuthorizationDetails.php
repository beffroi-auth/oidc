<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\AuthorizationDetails;

use function array_all;
use function array_any;
use function array_map;
use ArrayIterator;
use function count;
use Countable;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function in_array;
use IteratorAggregate;
use Traversable;

/**
 * RFC 9396 §2
 *
 * @implements IteratorAggregate<int, AuthorizationDetail>
 */
final readonly class AuthorizationDetails implements Countable, IteratorAggregate
{
    /**
     * @var non-empty-list<AuthorizationDetail>
     */
    public array $all;

    /**
     * @param list<AuthorizationDetail> $details
     *
     * @throws InvalidArgumentException when the set is empty
     */
    public function __construct(array $details)
    {
        $kept = [];
        foreach ($details as $detail) {
            if (! array_any($kept, static fn (AuthorizationDetail $seen): bool => $seen->equals($detail))) {
                $kept[] = $detail;
            }
        }
        if ($kept === []) {
            throw new InvalidArgumentException('A set of authorization details holds at least one detail (RFC 9396 section 2).');
        }
        $this->all = $kept;
    }

    public function has(AuthorizationDetail $detail): bool
    {
        return array_any($this->all, static fn (AuthorizationDetail $held): bool => $held->equals($detail));
    }

    public function covers(self $details): bool
    {
        return array_all($details->all, fn (AuthorizationDetail $detail): bool => $this->has($detail));
    }

    public function mergedWith(self $details): self
    {
        return new self([...$this->all, ...$details->all]);
    }

    /**
     * @return non-empty-list<string>
     */
    public function types(): array
    {
        $types = [];
        foreach ($this->all as $detail) {
            if (! in_array($detail->type, $types, true)) {
                $types[] = $detail->type;
            }
        }

        return $types;
    }

    /**
     * RFC 9396 §7, §9
     *
     * @return non-empty-list<non-empty-array<string, mixed>>
     */
    public function toClaim(): array
    {
        return array_map(static fn (AuthorizationDetail $detail): array => $detail->toClaim(), $this->all);
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
     * @return Traversable<int, AuthorizationDetail>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->all);
    }
}

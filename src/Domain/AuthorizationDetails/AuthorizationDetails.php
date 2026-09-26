<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\AuthorizationDetails;

use function array_all;
use function array_any;
use function array_map;
use ArrayIterator;
use function count;
use Countable;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function in_array;
use IteratorAggregate;
use Traversable;

/**
 * The details a request asks for (RFC 9396 §2): at least one, each asked for once, in the order it was
 * first seen. Everything that carries details holds one of these, so that what a set answers is answered
 * once: whether it holds a detail, whether it covers another set, and how it is written on the wire.
 *
 * At least one, because a request that asks for no detail carries no set at all: the absence is a null
 * and never an empty set, exactly as it is for the resources and for the scopes of a token.
 *
 * @implements IteratorAggregate<int, AuthorizationDetail>
 */
final readonly class AuthorizationDetails implements Countable, IteratorAggregate
{
    /**
     * @var non-empty-list<AuthorizationDetail> in the order they were first seen
     */
    public array $all;

    /**
     * @param list<AuthorizationDetail> $details at least one; a detail asked for twice counts once
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

    /**
     * Every detail of the other set is held here: what a consent has to cover for a request not to ask
     * again, and what a grant has to cover for the details a token request names (RFC 9396 §7).
     */
    public function covers(self $details): bool
    {
        return array_all($details->all, fn (AuthorizationDetail $detail): bool => $this->has($detail));
    }

    /**
     * The two sets as one, each detail once, the ones already held first: what a consent extended with a
     * new request agrees to, which is never less than what it agreed to before (architecture §4.3).
     */
    public function mergedWith(self $details): self
    {
        return new self([...$this->all, ...$details->all]);
    }

    /**
     * The types the set names, each once, in the order they were first seen: what a registration is
     * asked about, and what a page renders by.
     *
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
     * RFC 9396 §7, §9: the array an access token carries and an introspection renders.
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

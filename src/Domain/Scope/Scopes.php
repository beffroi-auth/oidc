<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Scope;

use function array_all;
use function array_any;
use function array_map;
use function count;
use ArrayIterator;
use Countable;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function implode;
use IteratorAggregate;
use Stringable;
use Traversable;

/**
 * A set of scopes as RFC 6749 §3.3 writes one: at least one, each named once, in the order it was first
 * seen. Everything this provider keeps a scope list on holds one of these, so that what a set answers is
 * answered once: whether it holds a scope, whether it covers another set, and how it is written on the
 * wire.
 *
 * At least one, because nothing here grants nothing: a request, a consent, a code, a token and a client
 * registration all name what they are for, and an empty set would be a promise with no content.
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
     * @param list<Scope> $scopes at least one; a scope named twice counts once
     *
     * @throws InvalidArgumentException when the set is empty
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
     * A "scope" parameter or claim, as it arrived.
     *
     * @throws InvalidArgumentException when a token is not a scope, the empty string included
     */
    public static function parse(string $scope): self
    {
        return new self(Scope::parseList($scope));
    }

    public function has(Scope $scope): bool
    {
        return array_any($this->all, static fn (Scope $held): bool => $held->equals($scope));
    }

    /**
     * Every scope of the other set is held here: what a consent has to cover for a request, and what a
     * refresh token has to cover for the scopes asked of it (RFC 6749 §6).
     */
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
     * A set is walked over as a set: what a page listing them does, and what a caller that needs the
     * list itself reads from "all".
     *
     * @return Traversable<int, Scope>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->all);
    }

    /**
     * Space-delimited, as RFC 6749 §3.3 writes it: what a token response, an introspection response and
     * an "at+jwt" all put on the wire, written once.
     */
    public function __toString(): string
    {
        return implode(' ', $this->all);
    }
}

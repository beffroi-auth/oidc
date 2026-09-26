<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\AuthorizationDetails;

use Heidi\Oidc\Exception\InvalidArgumentException;

/**
 * One type of authorization detail this provider serves (RFC 9396 §2), as the wiring hands it over: the
 * value of the "type" member it answers for, and what it makes of the members that came with it.
 *
 * A type is the only place that knows what its own detail means, so it is the only place that validates
 * one: which members it requires, which values they may take, what of it a token carries and what a page
 * says of it before the user agrees. A type the provider gains is a class here and a line in the wiring;
 * a type nobody wired is a type nobody serves, and a request naming one is refused rather than granted
 * something nothing can describe.
 *
 * Nothing enumerates the types, nothing reads a class name, and what the discovery document announces is
 * this wiring read (issue #98).
 */
interface AuthorizationDetailTypeInterface
{
    /**
     * The value of the "type" member this class answers for (RFC 9396 §2).
     *
     * @return non-empty-string
     */
    public function type(): string;

    /**
     * The detail these members stand for, validated by the type that accepts them: what an access token
     * will carry (§7), what an introspection will render (§9), and what a page will say of it.
     *
     * The members are built in an order of the type's own, so that two requests that ask for the same
     * thing produce the same detail whatever order they wrote it in, which is what lets a consent given
     * for one cover the other.
     *
     * @param array<string, mixed> $members the members of the object, "type" excluded
     *
     * @throws InvalidArgumentException when the members are not a detail of this type
     */
    public function of(array $members): AuthorizationDetail;
}

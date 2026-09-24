<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Token\ConfirmationInterface;
use Heidi\Oidc\Exception\InvalidArgumentException;

/**
 * Reads back what a token is bound to (RFC 7800 §3.1), whatever kept it: the claims of an "at+jwt" this
 * provider signed, the row of an opaque token, the members of an introspection response. It knows no
 * kind of its own; the kinds the provider is wired with say which members they answer for.
 */
interface ConfirmationReaderInterface
{
    /**
     * The claims of a token as they were written, read strictly: a "cnf" that is not an object, or that
     * names nothing this provider binds to, is a token this provider did not issue.
     *
     * @param array<array-key, mixed> $claims
     *
     * @throws InvalidArgumentException when the "cnf" names nothing this provider binds to
     */
    public function fromClaims(array $claims): ?ConfirmationInterface;

    /**
     * The members of a "cnf", however they were kept: read strictly, because a confirmation nobody can
     * read is a token bound to nothing.
     *
     * @param array<array-key, mixed> $members
     *
     * @throws InvalidArgumentException when no member is one this provider writes, when a member carries
     *                                  no thumbprint, or when several are there at once
     */
    public function fromMembers(array $members): ConfirmationInterface;
}

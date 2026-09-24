<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use Heidi\Oidc\Exception\InvalidArgumentException;

/**
 * One way this provider binds a token to what its holder proved (RFC 7800 §3.1), as the wiring hands it
 * over: the member of the "cnf" it is written under, the scheme the token is then presented with, and
 * how a thumbprint kept under that member is read back into the confirmation that speaks for it.
 *
 * A kind the provider gains is a class here and a line in the wiring. Nothing lists the members, nothing
 * lists the schemes, and nothing reads a class name: what the provider binds with is what it is wired
 * with, and what a resource accepts is derived from that same wiring (issue #98).
 */
interface ConfirmationKindInterface
{
    /**
     * The member of the "cnf" a confirmation of this kind is written under (RFC 7800 §3.1).
     *
     * @return non-empty-string
     */
    public function member(): string;

    /**
     * The scheme a token bound this way is presented with, which is also the "token_type" of the
     * response that handed it out (RFC 6749 §5.1).
     *
     * @return non-empty-string
     */
    public function scheme(): string;

    /**
     * The confirmation a thumbprint kept under this member stands for.
     *
     * @throws InvalidArgumentException when the value is not a thumbprint of this kind
     */
    public function of(string $thumbprint): ConfirmationInterface;
}

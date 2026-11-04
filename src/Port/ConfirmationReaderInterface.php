<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Token\ConfirmationInterface;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * RFC 7800 §3.1
 */
interface ConfirmationReaderInterface
{
    /**
     * @param array<array-key, mixed> $claims
     *
     * @throws InvalidArgumentException when the "cnf" is not an object or names nothing this provider binds to
     */
    public function fromClaims(array $claims): ?ConfirmationInterface;

    /**
     * @param array<array-key, mixed> $members
     *
     * @throws InvalidArgumentException when no member is one this provider writes, when a member carries no
     *                                  thumbprint, or when several are there at once
     */
    public function fromMembers(array $members): ConfirmationInterface;
}

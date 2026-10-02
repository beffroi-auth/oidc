<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

/**
 * A token this provider keeps by the digest of its value and never by the value itself
 * (architecture §4.6). It is what an event names when it says which token something happened to.
 */
interface HashedTokenInterface
{
    public string $tokenHash { get; }
}

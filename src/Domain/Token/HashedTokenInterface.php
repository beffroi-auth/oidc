<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

interface HashedTokenInterface
{
    public string $tokenHash { get; }
}

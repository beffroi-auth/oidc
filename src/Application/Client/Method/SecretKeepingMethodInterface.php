<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Method;

use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Oidc\Domain\Client\ClientSecretInterface;
use Beffroi\Oidc\Domain\Client\SecretBearingMethodInterface;
use SensitiveParameter;

interface SecretKeepingMethodInterface extends SecretBearingMethodInterface
{
    public function keep(#[SensitiveParameter] string $secret, PasswordHasherInterface $hasher): ClientSecretInterface;

    /**
     * RFC 7592 §2.2
     *
     * Compared in constant time, and never read back out of what is kept.
     */
    public function holdsSecret(#[SensitiveParameter] string $presented, ClientSecretInterface $kept): bool;
}

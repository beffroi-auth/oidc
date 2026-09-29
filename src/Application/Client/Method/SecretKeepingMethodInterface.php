<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Method;

use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Oidc\Domain\Client\ClientSecretInterface;
use Heidi\Oidc\Domain\Client\SecretBearingMethodInterface;
use SensitiveParameter;

/**
 * How a registered secret is kept for a method that verifies against one, and how one presented is
 * compared with what is kept. The domain says which shapes a method accepts
 * (SecretBearingMethodInterface); this says how a secret read from a registration is turned into one of
 * them and how one is recognised again, which needs the hasher of the core and therefore lives here.
 */
interface SecretKeepingMethodInterface extends SecretBearingMethodInterface
{
    public function keep(#[SensitiveParameter] string $secret, PasswordHasherInterface $hasher): ClientSecretInterface;

    /**
     * Whether the secret a client holds is that value (RFC 7592 §2.2): what a client echoes back when it
     * replaces its own registration is compared with what the provider keeps, in constant time, and never
     * read back out of it. False for a secret kept in a shape this method does not verify against, which
     * is a client of another method.
     */
    public function holdsSecret(#[SensitiveParameter] string $presented, ClientSecretInterface $kept): bool;
}

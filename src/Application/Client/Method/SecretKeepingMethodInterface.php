<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Method;

use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Oidc\Domain\Client\ClientSecretInterface;
use Heidi\Oidc\Domain\Client\SecretBearingMethodInterface;
use SensitiveParameter;

/**
 * How a registered secret is kept for a method that verifies against one. The domain says which shapes a
 * method accepts (SecretBearingMethodInterface); this says how a secret read from a registration is
 * turned into one of them, which needs the hasher of the core and therefore lives here.
 */
interface SecretKeepingMethodInterface extends SecretBearingMethodInterface
{
    public function keep(#[SensitiveParameter] string $secret, PasswordHasherInterface $hasher): ClientSecretInterface;
}

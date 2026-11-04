<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

interface SecretBearingMethodInterface extends ClientAuthenticationMethodInterface
{
    public function accepts(ClientSecretInterface $secret): bool;
}

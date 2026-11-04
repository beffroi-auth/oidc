<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;

interface ClientAuthenticationMethodsInterface
{
    /**
     * @return non-empty-list<ClientAuthenticationMethodInterface>
     */
    public function clientAuthenticationMethods(): array;
}

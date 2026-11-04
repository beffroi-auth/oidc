<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\ClientRegistration;

interface ClientSourceInterface extends ClientRepositoryInterface
{
    /**
     * @return iterable<ClientRegistration>
     */
    public function registrationsIn(Tenant $tenant): iterable;
}

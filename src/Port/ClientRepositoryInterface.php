<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Client;

interface ClientRepositoryInterface
{
    public function findByClientId(Tenant $tenant, string $clientId): ?Client;
}

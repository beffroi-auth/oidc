<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;

interface ClientRegistrationPolicyInterface
{
    /**
     * @return ClientRegistrationPolicy|null null for a tenant that registers nobody
     */
    public function policyFor(Tenant $tenant): ?ClientRegistrationPolicy;
}

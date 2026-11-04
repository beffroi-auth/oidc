<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Scope\Scope;

interface RegisteredScopesInterface
{
    /**
     * @return list<Scope> each named once
     */
    public function scopesRegisteredIn(Tenant $tenant): array;
}

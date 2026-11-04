<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Scope\Scope;

interface DeclaredScopesInterface
{
    /**
     * @return list<Scope> each named once, never "offline_access"
     */
    public function scopesDeclaredFor(Tenant $tenant): array;
}

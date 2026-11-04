<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Scope\Scope;

interface OfferedScopesInterface
{
    /**
     * @return non-empty-list<Scope> each named once, "openid" first
     */
    public function scopesOfferedIn(Tenant $tenant): array;
}

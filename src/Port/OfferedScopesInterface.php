<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Scope\Scope;

/**
 * Every scope a tenant hands out tokens for: what a client of it may ask for, what the discovery
 * document of it announces, and what a client that registers itself may register (decision 0009). One
 * question with one answer, because a provider that announced one set and registered against another
 * would be two places that must agree.
 *
 * It is not the same question as `RegisteredScopesInterface`, which is one of the things this is made
 * of: what the clients of the tenant registered, beside what a wired claims provider serves and what a
 * wired grant makes good.
 */
interface OfferedScopesInterface
{
    /**
     * @return non-empty-list<Scope> each named once, "openid" first, this being an OpenID provider
     */
    public function scopesOfferedIn(Tenant $tenant): array;
}

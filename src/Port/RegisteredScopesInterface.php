<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Scope\Scope;

/**
 * Which scopes the clients registered for a tenant registered, read from them and kept nowhere beside them
 * (issue #98). It is one of the two places a scope that stands for no claim, the one an API is protected by,
 * comes from: a client of the tenant registered for it (issue #278), or the deployment declares it for the
 * tenant (`DeclaredScopesInterface`, issue #920). The provider has nothing else to learn one from, the "scope"
 * a client registers being a closed list it is held to.
 *
 * What reads it is the document the provider publishes: a client learns there which "scope" values exist
 * at all, a typo in a registration being announced rather than granted in silence.
 *
 * It asks about the set of clients and not about one of them, which is why it is not the repository that
 * resolves a client: a caller that looks a client up never asks this, and a caller that asks this never
 * looks a client up.
 */
interface RegisteredScopesInterface
{
    /**
     * @return list<Scope> each named once, in the order the clients were registered; empty when no client
     *                    of that tenant is registered for any scope
     */
    public function scopesRegisteredIn(Tenant $tenant): array;
}

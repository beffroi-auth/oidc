<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Scope\Scope;

/**
 * Which scopes a tenant hands out tokens for beyond those a wired claims provider serves, which is what
 * the clients registered for it registered and nothing kept beside them (issue #98). A scope that stands
 * for no claim, the one an API is protected by, exists because a client of this tenant was registered for
 * it and for no other reason: the provider has nothing else to learn it from, the "scope" a client registers
 * being a closed list it is held to.
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

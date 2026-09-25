<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\AccessTokenShapeInterface;

/**
 * Which shapes of access token a tenant actually hands out (architecture §4.6), which is what the
 * clients declared for it registered and nothing kept beside them (issue #98). What reads it is the
 * retirement of a signing key: a key that signed an "at+jwt" stays published until the last one it
 * signed has expired, and a tenant no client takes that shape from has nothing to wait for.
 *
 * It asks about the set of clients and not about one of them, which is why it is not the repository that
 * resolves a client: a caller that looks a client up never asks this, and a caller that asks this never
 * looks a client up.
 */
interface RegisteredAccessTokenShapesInterface
{
    /**
     * Whether a client of this tenant is registered for the shape, compared by the name both sides give
     * it and never by the instance either of them holds.
     */
    public function issuesAccessTokensIn(Tenant $tenant, AccessTokenShapeInterface $shape): bool;
}

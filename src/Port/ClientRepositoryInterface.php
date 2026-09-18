<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Domain\Client\Client;

/**
 * Where the clients of a tenant come from: the bundle configuration in the first spike, a database and
 * dynamic registration (RFC 7591) later. The port does not change (architecture §4.1).
 */
interface ClientRepositoryInterface
{
    /**
     * @param string $clientId as the client presented it; the match is exact
     */
    public function findByClientId(Tenant $tenant, string $clientId): ?Client;

    /**
     * Whether a client of the tenant is registered for access tokens of this shape (architecture §4.6): what
     * decides, at a rotation, whether a self-contained access token can be alive and holds a key back.
     */
    public function issuesAccessTokensIn(Tenant $tenant, AccessTokenFormat $format): bool;
}

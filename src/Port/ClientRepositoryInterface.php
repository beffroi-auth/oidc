<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Domain\Client\Client;

/**
 * Where the clients of a tenant come from (architecture §4.1).
 */
interface ClientRepositoryInterface
{
    public function findByClientId(Tenant $tenant, string $clientId): ?Client;

    /**
     * What decides, at a rotation, whether a self-contained access token can be alive (architecture §4.6).
     */
    public function issuesAccessTokensIn(Tenant $tenant, AccessTokenFormat $format): bool;
}

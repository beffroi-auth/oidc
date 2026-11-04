<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\AccessTokenShapeInterface;

interface RegisteredAccessTokenShapesInterface
{
    /**
     * Compares shapes by the name both sides give them, never by instance.
     */
    public function issuesAccessTokensIn(Tenant $tenant, AccessTokenShapeInterface $shape): bool;
}

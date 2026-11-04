<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;

/**
 * RFC 9126 §5
 *
 * Required of a tenant only when every client registered there requires it.
 */
interface PushedAuthorizationRequirementInterface
{
    public function requiresPushedAuthorizationRequests(Tenant $tenant): bool;
}

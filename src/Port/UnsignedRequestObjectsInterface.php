<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;

/**
 * True when a client of the tenant registered "request_object_signing_alg": "none" (OIDC Registration §2).
 */
interface UnsignedRequestObjectsInterface
{
    public function acceptsUnsignedRequestObjects(Tenant $tenant): bool;
}

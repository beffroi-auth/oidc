<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Tenant\Tenant;

/**
 * Whether a client of a tenant registered "request_object_signing_alg": "none" (OIDC Registration §2).
 * The document says what is wired and nothing else (issue #98): "none" is announced in
 * "request_object_signing_alg_values_supported" when a client registered it and is absent otherwise, so
 * that a deployment whose clients all sign their request objects never announces that it would read an
 * unsigned one.
 */
interface UnsignedRequestObjectsInterface
{
    public function acceptsUnsignedRequestObjects(Tenant $tenant): bool;
}

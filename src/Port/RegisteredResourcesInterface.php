<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Resource\ResourceIndicator;

/**
 * Which resources a tenant hands out access tokens for (RFC 8707 §2), which is what the clients
 * declared for it registered and nothing kept beside them (issue #98). What reads it is the document
 * the provider publishes: a client learns there which "resource" values exist at all.
 *
 * It asks about the set of clients and not about one of them, which is why it is not the repository
 * that resolves a client: a caller that looks a client up never asks this, and a caller that asks this
 * never looks a client up.
 */
interface RegisteredResourcesInterface
{
    /**
     * @return list<ResourceIndicator> each named once, in the order the clients were declared; empty
     *                                 when no client of that tenant is registered for any resource
     */
    public function resourcesRegisteredIn(Tenant $tenant): array;
}

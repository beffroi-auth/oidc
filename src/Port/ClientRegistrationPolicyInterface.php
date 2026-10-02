<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;

/**
 * What a tenant does with a client that registers itself (decision 0009). The core knows no protocol, so
 * this is not a field of its `Tenant`: it is one question about one tenant, asked through a port of its
 * own, as whether that tenant reads unsigned request objects is (`UnsignedRequestObjectsInterface`).
 *
 * Closed is the default and closed is what a deployment that writes nothing gets: a tenant with no
 * policy has no registration endpoint at all, which is what the document says of it and what the
 * endpoint answers for it.
 */
interface ClientRegistrationPolicyInterface
{
    /**
     * @return ClientRegistrationPolicy|null null for a tenant that registers nobody, which is every
     *                                       tenant a deployment wrote no policy for
     */
    public function policyFor(Tenant $tenant): ?ClientRegistrationPolicy;
}

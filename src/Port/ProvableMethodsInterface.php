<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use LogicException;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Tenant\Tenant;

/**
 * What a login at this provider can prove, as "amr" values, every way of signing in together; the
 * integration wires the logins, so it says (architecture §5.4). The classes of a tenant's policy whose
 * predicate these methods satisfy are what the discovery announces and what a step-up may ask for
 * (decision 0010).
 */
interface ProvableMethodsInterface
{
    /**
     * @throws LogicException when the integration wires no login at all, or one it cannot read, or when the
     *                        floor of this tenant admits none of the logins it wires: what a provider
     *                        announces it can prove is read from its logins, so having none left is a
     *                        provider nobody can sign in to, not a provider that proves nothing
     * @return non-empty-list<AuthenticationMethod>
     */
    public function provableMethods(Tenant $tenant): array;
}

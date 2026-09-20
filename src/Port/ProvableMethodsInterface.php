<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Session\AuthenticationMethod;

/**
 * What a login at this provider can prove, as "amr" values, every way of signing in together; the
 * integration wires the logins, so it says (architecture §5.4). The classes of a tenant's policy whose
 * predicate these methods satisfy are what the discovery announces and what a step-up may ask for
 * (decision 0010).
 */
interface ProvableMethodsInterface
{
    /**
     * @return non-empty-list<AuthenticationMethod>
     */
    public function provableMethods(): array;
}

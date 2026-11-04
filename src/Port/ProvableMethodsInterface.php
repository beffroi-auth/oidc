<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use LogicException;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Tenant\Tenant;

interface ProvableMethodsInterface
{
    /**
     * @throws LogicException when the integration wires no login at all, or one it cannot read, or when the floor of
     *                        this tenant admits none of the logins it wires
     *
     * @return non-empty-list<AuthenticationMethod>
     */
    public function provableMethods(Tenant $tenant): array;
}

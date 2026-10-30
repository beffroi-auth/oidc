<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Scope\Scope;

/**
 * Which scopes a tenant hands out tokens for because its deployment declares them (issue #920): the scopes of the
 * APIs it protects, which stand for no claim and exist before any client does. A deployment that declares no client,
 * which is every deployment of the image (decision 0030), has nothing else to make one exist: what the clients of a
 * tenant registered is the other source of such a scope (`RegisteredScopesInterface`), and a client that registers
 * itself is held to what its tenant already offers (decision 0009).
 *
 * "offline_access" is never one of them: it asks for a refresh token (OIDC Core §11), and whether the provider can
 * make one good is what its wired grants say and nothing a deployment declares.
 */
interface DeclaredScopesInterface
{
    /**
     * @return list<Scope> each named once, in the order the deployment declared them, never "offline_access"; empty
     *                     for a tenant whose deployment declares none
     */
    public function scopesDeclaredFor(Tenant $tenant): array;
}

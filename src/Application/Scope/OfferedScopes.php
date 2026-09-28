<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Scope;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Port\ClaimsProviderInterface;
use Heidi\Oidc\Port\OfferedScopesInterface;
use Heidi\Oidc\Port\RegisteredScopesInterface;
use Heidi\Oidc\Port\ServedGrantsInterface;

/**
 * Every scope a tenant hands out tokens for, assembled where it is assembled once (issue #98):
 *
 * - "openid", always, this being an OpenID provider;
 * - what the wired claims providers serve, which stand for claims (OIDC Core §5.4);
 * - what the clients of the tenant registered, which is where a scope that stands for no claim comes
 *   from, an API being protected by one and a registration being the only thing that says it exists
 *   (issue #278);
 * - "offline_access", where the provider can make it good (OIDC Core §11), which is where a wired grant
 *   issues a refresh token and a wired grant spends one. A registration alone never puts it here: a
 *   client that registered it on a deployment whose grants do not make it good would have the provider
 *   promise a refresh token its token endpoint would not issue.
 *
 * The document announces this (`AnnouncedScopes`) and a registration is held to it, which is the reason
 * it is one class: a typo in a registration is announced rather than granted in silence, and a client
 * that registers itself is held to what a declared client of the same tenant is held to.
 */
final readonly class OfferedScopes implements OfferedScopesInterface
{
    public function __construct(
        private ClaimsProviderInterface $claims,
        private ServedGrantsInterface $grants,
        private RegisteredScopesInterface $registered,
    ) {
    }

    public function scopesOfferedIn(Tenant $tenant): array
    {
        $offlineAccess = Scope::offlineAccess();
        $offered = [Scope::openid(), ...$this->claims->supportedScopes()];
        foreach ($this->registered->scopesRegisteredIn($tenant) as $scope) {
            if (! $scope->equals($offlineAccess)) {
                $offered[] = $scope;
            }
        }
        if ($this->grants->issuingRefreshTokens() !== [] && $this->grants->spendingRefreshTokens() !== []) {
            $offered[] = $offlineAccess;
        }

        return new Scopes($offered)->all;
    }
}

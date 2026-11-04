<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Scope;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Port\ClaimsProviderInterface;
use Beffroi\Oidc\Port\DeclaredScopesInterface;
use Beffroi\Oidc\Port\OfferedScopesInterface;
use Beffroi\Oidc\Port\RegisteredScopesInterface;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * "offline_access" is never offered on a registration alone: the token endpoint might not issue what it promises.
 */
final readonly class OfferedScopes implements OfferedScopesInterface
{
    public function __construct(
        private ClaimsProviderInterface $claims,
        private ServedGrantsInterface $grants,
        private RegisteredScopesInterface $registered,
        private DeclaredScopesInterface $declared,
    ) {
    }

    public function scopesOfferedIn(Tenant $tenant): array
    {
        $offlineAccess = Scope::offlineAccess();
        $offered = [Scope::openid(), ...$this->claims->supportedScopes(), ...$this->declared->scopesDeclaredFor($tenant)];
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

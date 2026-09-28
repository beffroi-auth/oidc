<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Port\ClaimsProviderInterface;
use Heidi\Oidc\Port\MetadataContributorInterface;
use Heidi\Oidc\Port\RegisteredScopesInterface;
use Heidi\Oidc\Port\ServedGrantsInterface;

/**
 * OIDC Discovery §3: the scopes a client may ask for. "openid" is always among them, since this is an
 * OpenID provider, and "offline_access" only where the provider can make it good (OIDC Core §11), which
 * is where a wired grant issues a refresh token and a wired grant spends one: announcing a scope
 * nothing honours would be a promise the token endpoint breaks. Which grants those are, they say
 * themselves.
 *
 * Between the two, the scopes that exist for this tenant: those the wired claims providers serve, which
 * stand for claims (§5.4), and those the clients of the tenant registered, which is where a scope that
 * stands for no claim comes from (issue #98). An API is protected by such a scope, and a registration is
 * the only thing that says it exists; announcing it is what makes a typo in a registration visible
 * instead of granted in silence.
 *
 * "offline_access" is the one scope a registration does not put here: a client that registered it on a
 * deployment whose grants do not make it good would have the document promise a refresh token the token
 * endpoint would not issue.
 */
final readonly class AnnouncedScopes implements MetadataContributorInterface
{
    public function __construct(
        private ClaimsProviderInterface $claims,
        private ServedGrantsInterface $grants,
        private RegisteredScopesInterface $registered,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $offlineAccess = Scope::offlineAccess();
        $announced = [Scope::openid(), ...$this->claims->supportedScopes()];
        foreach ($this->registered->scopesRegisteredIn($tenant) as $scope) {
            if (! $scope->equals($offlineAccess)) {
                $announced[] = $scope;
            }
        }
        if ($this->grants->issuingRefreshTokens() !== [] && $this->grants->spendingRefreshTokens() !== []) {
            $announced[] = $offlineAccess;
        }

        return [
            'scopes_supported' => new Scopes($announced)->values(),
        ];
    }
}

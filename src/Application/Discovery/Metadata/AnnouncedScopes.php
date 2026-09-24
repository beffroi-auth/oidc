<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Port\ClaimsProviderInterface;
use Heidi\Oidc\Application\Discovery\ServedGrantTypes;
use Heidi\Oidc\Port\MetadataContributorInterface;
use function in_array;

/**
 * OIDC Discovery §3: the scopes a client may ask for. "openid" is always among them, since this is an
 * OpenID provider, and "offline_access" only when the refresh token grant is served (OIDC Core §11):
 * announcing a scope nothing honours would be a promise the token endpoint breaks.
 */
final readonly class AnnouncedScopes implements MetadataContributorInterface
{
    public function __construct(
        private ClaimsProviderInterface $claims,
        private ServedGrantTypes $grantTypes,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $announced = [Scope::openid(), ...$this->claims->supportedScopes()];
        if (in_array(GrantType::RefreshToken, $this->grantTypes->all, true)) {
            $announced[] = Scope::offlineAccess();
        }

        return [
            'scopes_supported' => new Scopes($announced)->values(),
        ];
    }
}

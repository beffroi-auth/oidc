<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Port\ClaimsProviderInterface;
use Heidi\Oidc\Port\MetadataContributorInterface;
use Heidi\Oidc\Port\ServedGrantsInterface;

/**
 * OIDC Discovery §3: the scopes a client may ask for. "openid" is always among them, since this is an
 * OpenID provider, and "offline_access" only where the provider can make it good (OIDC Core §11), which
 * is where a wired grant issues a refresh token and a wired grant spends one: announcing a scope
 * nothing honours would be a promise the token endpoint breaks. Which grants those are, they say
 * themselves.
 */
final readonly class AnnouncedScopes implements MetadataContributorInterface
{
    public function __construct(
        private ClaimsProviderInterface $claims,
        private ServedGrantsInterface $grants,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $announced = [Scope::openid(), ...$this->claims->supportedScopes()];
        if ($this->grants->issuingRefreshTokens() !== [] && $this->grants->spendingRefreshTokens() !== []) {
            $announced[] = Scope::offlineAccess();
        }

        return [
            'scopes_supported' => new Scopes($announced)->values(),
        ];
    }
}

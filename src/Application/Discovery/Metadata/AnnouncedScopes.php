<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Port\MetadataContributorInterface;
use Heidi\Oidc\Port\OfferedScopesInterface;

/**
 * OIDC Discovery §3: the scopes a client may ask for, which are the scopes the tenant hands out tokens
 * for and are read where they are assembled (`OfferedScopes`). What the document announces and what a
 * registration is held to is one set, because a provider that announced one and registered against
 * another would be two places that must agree.
 */
final readonly class AnnouncedScopes implements MetadataContributorInterface
{
    public function __construct(
        private OfferedScopesInterface $scopes,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        return [
            'scopes_supported' => new Scopes($this->scopes->scopesOfferedIn($tenant))->values(),
        ];
    }
}

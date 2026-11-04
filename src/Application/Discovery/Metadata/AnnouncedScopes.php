<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use Beffroi\Oidc\Port\OfferedScopesInterface;

/**
 * OIDC Discovery §3
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

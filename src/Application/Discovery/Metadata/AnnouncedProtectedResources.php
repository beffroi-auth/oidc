<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use Beffroi\Oidc\Port\RegisteredResourcesInterface;

/**
 * RFC 9728 §4
 *
 * With no resource registered, nothing is announced: an empty list would read as "no resource is acceptable".
 */
final readonly class AnnouncedProtectedResources implements MetadataContributorInterface
{
    public function __construct(
        private RegisteredResourcesInterface $resources,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $resources = $this->resources->resourcesRegisteredIn($tenant);
        if ($resources === []) {
            return [];
        }

        return [
            'protected_resources' => new ResourceIndicators($resources)->values(),
        ];
    }
}

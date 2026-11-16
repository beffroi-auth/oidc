<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use function array_filter;
use function array_values;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Port\AdministrationResourceInterface;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use Beffroi\Oidc\Port\RegisteredResourcesInterface;

/**
 * RFC 9728 §4
 *
 * With no resource registered, nothing is announced: an empty list would read as "no resource is acceptable". The
 * administration API is never announced (decision 0038).
 */
final readonly class AnnouncedProtectedResources implements MetadataContributorInterface
{
    public function __construct(
        private RegisteredResourcesInterface $resources,
        private AdministrationResourceInterface $administration,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $administration = $this->administration->administrationResourceOf($tenant);
        $resources = array_values(array_filter(
            $this->resources->resourcesRegisteredIn($tenant),
            static fn (ResourceIndicator $resource): bool => $administration === null || ! $resource->equals($administration),
        ));
        if ($resources === []) {
            return [];
        }

        return [
            'protected_resources' => new ResourceIndicators($resources)->values(),
        ];
    }
}

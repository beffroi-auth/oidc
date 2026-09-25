<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Port\MetadataContributorInterface;
use Heidi\Oidc\Port\RegisteredResourcesInterface;

/**
 * RFC 9728 §4 "protected_resources": the resources a client of this tenant may name in a "resource"
 * parameter (RFC 8707 §2), which is the one member of the registry that says what those values are.
 * RFC 8707 registers none of its own.
 *
 * What is announced is what the clients of the tenant registered, read from them and not kept beside
 * them (issue #98). A tenant whose clients registered none announces nothing: the member would be an
 * empty list, which a client would read as "no resource is acceptable here" rather than as "this
 * provider does not enumerate them".
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

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use Beffroi\Oidc\Port\ServedAuthorizationDetailTypesInterface;

/**
 * RFC 9396 §10
 *
 * Absent when no type is wired: an empty list would read as no type being acceptable.
 */
final readonly class AnnouncedAuthorizationDetails implements MetadataContributorInterface
{
    public function __construct(
        private ServedAuthorizationDetailTypesInterface $types,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $types = $this->types->servedAuthorizationDetailTypes();
        if ($types === []) {
            return [];
        }

        return [
            'authorization_details_types_supported' => $types,
        ];
    }
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Token\GrantNames;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * OIDC Discovery §3
 */
final readonly class AnnouncedGrants implements MetadataContributorInterface
{
    public function __construct(
        private ServedGrantsInterface $grants,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        return [
            'grant_types_supported' => GrantNames::of($this->grants->servedGrantTypes()),
        ];
    }
}

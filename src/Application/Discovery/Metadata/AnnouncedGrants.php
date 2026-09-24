<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Token\GrantNames;
use Heidi\Oidc\Port\MetadataContributorInterface;
use Heidi\Oidc\Port\ServedGrantsInterface;

/**
 * OIDC Discovery §3: the grants the token endpoint serves, which are the ones wired into it and not an
 * enumeration kept beside them. They name themselves, so a grant the provider gains is announced by the
 * fact of being served.
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

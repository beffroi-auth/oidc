<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use function array_map;
use function array_unique;
use function array_values;
use const SORT_REGULAR;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Application\Discovery\ServedGrantTypes;
use Heidi\Oidc\Port\MetadataContributorInterface;

/**
 * OIDC Discovery §3: the grants the token endpoint serves, which are the ones wired into it and not an
 * enumeration kept beside them.
 */
final readonly class AnnouncedGrants implements MetadataContributorInterface
{
    public function __construct(
        private ServedGrantTypes $grantTypes,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $grants = array_values(array_unique($this->grantTypes->all, SORT_REGULAR));

        return [
            'grant_types_supported' => array_map(static fn (GrantType $grant): string => $grant->value, $grants),
        ];
    }
}

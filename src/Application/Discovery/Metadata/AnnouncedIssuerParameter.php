<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\MetadataContributorInterface;

/**
 * RFC 9207 §3
 */
final readonly class AnnouncedIssuerParameter implements MetadataContributorInterface
{
    public function metadata(Tenant $tenant): array
    {
        return [
            'authorization_response_iss_parameter_supported' => true,
        ];
    }
}

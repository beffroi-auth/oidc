<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\MetadataContributorInterface;

/**
 * RFC 9207 §3: every authorization response carries "iss", which decision 0006 makes a rule and not an
 * option, so this is announced and never negotiated.
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

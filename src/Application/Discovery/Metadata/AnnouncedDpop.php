<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Heidi\Oidc\Port\MetadataContributorInterface;

/**
 * RFC 9449 §5.1: what a proof of possession may be signed with, which is what the provider is wired with
 * and verifies every other signature with; a client binding its tokens to a key signs with one of these
 * and with nothing else.
 */
final readonly class AnnouncedDpop implements MetadataContributorInterface
{
    public function __construct(
        private AnnouncedAlgorithms $algorithms,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        return [
            'dpop_signing_alg_values_supported' => $this->algorithms->signing(),
        ];
    }
}

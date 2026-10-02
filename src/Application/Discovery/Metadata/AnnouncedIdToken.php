<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Port\MetadataContributorInterface;

/**
 * OIDC Discovery §3: what an ID token is signed with, and what a client may have it encrypted to
 * (OIDC Core §3.1.3.7).
 */
final readonly class AnnouncedIdToken implements MetadataContributorInterface
{
    public function __construct(
        private AnnouncedAlgorithms $algorithms,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        return [
            'id_token_signing_alg_values_supported' => $this->algorithms->signing(),
            ...$this->algorithms->encryptionOf('id_token_encryption'),
        ];
    }
}

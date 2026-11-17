<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Application\Key\HeldSigningAlgorithms;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Application\Key\AlgorithmNames;
use Beffroi\Oidc\Port\MetadataContributorInterface;

/**
 * OIDC Discovery §3
 */
final readonly class AnnouncedIdToken implements MetadataContributorInterface
{
    public function __construct(
        private AnnouncedAlgorithms $algorithms,
        private HeldSigningAlgorithms $held,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        return [
            'id_token_signing_alg_values_supported' => AlgorithmNames::of($this->held->of($tenant)),
            ...$this->algorithms->encryptionOf('id_token_encryption'),
        ];
    }
}

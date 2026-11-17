<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Application\Key\HeldSigningAlgorithms;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Application\Key\AlgorithmNames;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use Beffroi\Oidc\Port\ServedResponseModesInterface;

/**
 * JARM §3
 */
final readonly class AnnouncedSignedAuthorizationResponse implements MetadataContributorInterface
{
    public function __construct(
        private ServedResponseModesInterface $responseModes,
        private AnnouncedAlgorithms $algorithms,
        private HeldSigningAlgorithms $held,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        if (! $this->responseModes->signsAnyAnswer()) {
            return [];
        }

        return [
            'authorization_signing_alg_values_supported' => AlgorithmNames::of($this->held->of($tenant)),
            ...$this->algorithms->encryptionOf('authorization_encryption'),
        ];
    }
}

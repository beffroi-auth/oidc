<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use Beffroi\Oidc\Port\ServedResponseModesInterface;

/**
 * JARM §3: what a signed authorization response is signed with, which is what the provider signs every
 * other JWS with, and what it may be encrypted to a key of the client with. A deployment that wires no
 * signed mode announces nothing at all here rather than empty lists: there is no answer to sign.
 */
final readonly class AnnouncedSignedAuthorizationResponse implements MetadataContributorInterface
{
    public function __construct(
        private ServedResponseModesInterface $responseModes,
        private AnnouncedAlgorithms $algorithms,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        if (! $this->responseModes->signsAnyAnswer()) {
            return [];
        }

        return [
            'authorization_signing_alg_values_supported' => $this->algorithms->signing(),
            ...$this->algorithms->encryptionOf('authorization_encryption'),
        ];
    }
}

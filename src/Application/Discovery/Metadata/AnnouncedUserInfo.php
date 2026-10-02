<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Port\MetadataContributorInterface;

/**
 * OIDC Discovery §3 and OIDC Core §5.3.2: a client may have the UserInfo answer as a JWT signed by the
 * tenant, encrypted, or both; one that registers none of these keeps the JSON.
 */
final readonly class AnnouncedUserInfo implements MetadataContributorInterface
{
    public function __construct(
        private AnnouncedAlgorithms $algorithms,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        return [
            'userinfo_signing_alg_values_supported' => $this->algorithms->signing(),
            ...$this->algorithms->encryptionOf('userinfo_encryption'),
        ];
    }
}

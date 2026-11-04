<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Claims\Sector;

use Beffroi\Oidc\Domain\Claims\SectorIdentifier;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Port\SectorIdentifierSourceInterface;

/**
 * OIDC Core §8.1
 */
final readonly class RegisteredSectorIdentifier implements SectorIdentifierSourceInterface
{
    public function sectorOf(ClientRegistration $registration): ?SectorIdentifier
    {
        return $registration->sectorIdentifierUri === null
            ? null
            : new SectorIdentifier($registration->sectorIdentifierUri->host);
    }

    public function publishedUris(ClientRegistration $registration): array
    {
        return [];
    }
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Claims\Sector;

use Beffroi\Oidc\Domain\Claims\SectorIdentifier;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Port\SectorIdentifierSourceInterface;

/**
 * CIBA Core §4
 */
final readonly class JwksUriSectorIdentifier implements SectorIdentifierSourceInterface
{
    public function sectorOf(ClientRegistration $registration): ?SectorIdentifier
    {
        $jwksUri = self::standsForTheSector($registration);

        return $jwksUri === null ? null : new SectorIdentifier($jwksUri);
    }

    public function publishedUris(ClientRegistration $registration): array
    {
        $jwksUri = self::standsForTheSector($registration);

        return $jwksUri === null ? [] : [(string) $registration->jwksUri];
    }

    private static function standsForTheSector(ClientRegistration $registration): ?string
    {
        return $registration->redirectUris === [] ? $registration->jwksUri?->host : null;
    }
}

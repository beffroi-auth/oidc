<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Claims\Sector;

use Beffroi\Oidc\Domain\Claims\SectorIdentifier;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\KeyBearingMethodInterface;
use Beffroi\Oidc\Port\SectorIdentifierSourceInterface;

/**
 * CIBA Core §4
 *
 * The host of the jwks_uri of a client that authenticates with a key published there, which every token it is handed
 * proves it holds, and whose identifiers no redirection carries.
 */
final readonly class JwksUriSectorIdentifier implements SectorIdentifierSourceInterface
{
    public function __construct(
        private IdentifiersWithoutARedirection $withoutARedirection,
    ) {
    }

    public function sectorOf(ClientRegistration $registration): ?SectorIdentifier
    {
        $jwksUri = $this->standsForTheSector($registration);

        return $jwksUri === null ? null : new SectorIdentifier($jwksUri);
    }

    public function publishedUris(ClientRegistration $registration): array
    {
        $jwksUri = $this->standsForTheSector($registration);

        return $jwksUri === null ? [] : [(string) $registration->jwksUri];
    }

    private function standsForTheSector(ClientRegistration $registration): ?string
    {
        if ($registration->redirectUris !== [] && ! $this->withoutARedirection->reach($registration)) {
            return null;
        }
        if (! $registration->authenticationMethod instanceof KeyBearingMethodInterface) {
            return null;
        }

        return $registration->jwksUri?->host;
    }
}

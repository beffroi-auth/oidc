<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Claims\Sector;

use Beffroi\Oidc\Domain\Claims\SectorIdentifier;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Port\SectorIdentifierSourceInterface;

/**
 * CIBA Core §4: the sector of a client that registers no redirection URI at all, the host of its
 * "jwks_uri". A client of the backchannel flow is asked for no redirection URI, because nothing of that
 * flow sends a browser anywhere, so OIDC Core §8.1 has no input for it and this is what stands in.
 *
 * **It is read from what the client registered and never from the flow the provider serves it**: what this
 * answers of is a client that registered no redirection URI, whatever grants it holds. A client that
 * registered one is answered by the source that reads those (`RedirectUriSectorIdentifier`), and this says
 * nothing of it, so an ordinary client is never given the sector of its keys by accident.
 *
 * Push mode is where CIBA Core §4 puts the notification endpoint instead, and this provider does not serve
 * push: that source is the class this one would sit beside the day it did.
 */
final readonly class JwksUriSectorIdentifier implements SectorIdentifierSourceInterface
{
    public function sectorOf(ClientRegistration $registration): ?SectorIdentifier
    {
        $jwksUri = self::standsForTheSector($registration);

        return $jwksUri === null ? null : new SectorIdentifier($jwksUri);
    }

    /**
     * CIBA Core §4: a client whose sector is read from its "jwks_uri" and which registers a
     * "sector_identifier_uri" beside it publishes that "jwks_uri" in the document, as a client of §8.1
     * publishes its redirection URIs. A client this source says nothing of asks for nothing there, which
     * is what keeps an ordinary client's keys out of a document that has no business naming them.
     */
    public function publishedUris(ClientRegistration $registration): array
    {
        $jwksUri = self::standsForTheSector($registration);

        return $jwksUri === null ? [] : [(string) $registration->jwksUri];
    }

    /**
     * The host of the "jwks_uri" when it is what says which sector this client is of, null otherwise.
     */
    private static function standsForTheSector(ClientRegistration $registration): ?string
    {
        return $registration->redirectUris === [] ? $registration->jwksUri?->host : null;
    }
}

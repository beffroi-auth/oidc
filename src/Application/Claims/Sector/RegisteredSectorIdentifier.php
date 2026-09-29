<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Claims\Sector;

use Heidi\Oidc\Domain\Claims\SectorIdentifier;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Port\SectorIdentifierSourceInterface;

/**
 * OIDC Core §8.1: the sector a client registered to say so, the host of its "sector_identifier_uri". It is
 * the first source wired and it answers before the others, because it is the one a client writes on
 * purpose: a client that names its sector is in the sector it named, and what the others would have read
 * of it is what it publishes to back the claim (OIDC Registration §5).
 *
 * It reads no URI of the client, so it asks for none in that document: the document is the claim, and a
 * claim does not name itself.
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

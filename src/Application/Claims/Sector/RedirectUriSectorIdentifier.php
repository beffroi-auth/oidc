<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Claims\Sector;

use function array_keys;
use function count;
use Beffroi\Oidc\Domain\Claims\SectorIdentifier;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\SectorIdentifierSourceInterface;
use function implode;
use function array_map;
use function sprintf;

/**
 * OIDC Core §8.1: the sector of a client that named none, the host its browser comes back to. A client
 * whose redirection URIs are on one host is of that host's sector; one whose URIs are on several names no
 * sector by registering them, and §8.1 answers that with a "sector_identifier_uri", which is another
 * source and answers before this one.
 *
 * A client that registers no redirection URI registers nothing this reads, and this says nothing of it:
 * what such a client is of is another source's to answer (CIBA Core §4, `JwksUriSectorIdentifier`).
 */
final readonly class RedirectUriSectorIdentifier implements SectorIdentifierSourceInterface
{
    public function sectorOf(ClientRegistration $registration): ?SectorIdentifier
    {
        if ($registration->redirectUris === []) {
            return null;
        }
        $hosts = [];
        foreach ($registration->redirectUris as $redirectUri) {
            $hosts[$redirectUri->host] = true;
        }
        if (count($hosts) !== 1) {
            throw new InvalidArgumentException(sprintf(
                'The client "%s" registers redirection URIs on %s, so it registers a sector_identifier_uri to say which sector its subject identifiers belong to (OIDC Core section 8.1).',
                $registration->clientId,
                implode(' and ', array_keys($hosts)),
            ));
        }

        return new SectorIdentifier($registration->redirectUris[0]->host);
    }

    /**
     * Every redirection URI it registered, and not only the one the host was read from: the document of a
     * registered sector names the clients of that sector by where their browsers come back to, so a URI
     * left out of it is a URI nobody vouched for (OIDC Registration §5).
     */
    public function publishedUris(ClientRegistration $registration): array
    {
        return array_map(
            static fn (RedirectUri $redirectUri): string => $redirectUri->value,
            $registration->redirectUris,
        );
    }
}

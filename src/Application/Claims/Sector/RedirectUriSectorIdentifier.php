<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Claims\Sector;

use function array_keys;
use function array_map;
use function count;
use Beffroi\Oidc\Domain\Claims\SectorIdentifier;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\SectorIdentifierSourceInterface;
use function implode;
use function sprintf;

/**
 * OIDC Core §4, §8.1
 *
 * The host the identifiers of a person reach the client on, which only a redirection vouches for: the redirection URIs
 * and the initiate_login_uri of a client no other grant hands them to.
 */
final readonly class RedirectUriSectorIdentifier implements SectorIdentifierSourceInterface
{
    public function __construct(
        private IdentifiersWithoutARedirection $withoutARedirection,
    ) {
    }

    public function sectorOf(ClientRegistration $registration): ?SectorIdentifier
    {
        if (! $this->standsForTheSector($registration)) {
            return null;
        }
        $hosts = [];
        foreach ($registration->redirectUris as $redirectUri) {
            $hosts[$redirectUri->host] = true;
        }
        if ($registration->initiateLoginUri !== null) {
            $hosts[$registration->initiateLoginUri->host] = true;
        }
        if (count($hosts) !== 1) {
            throw new InvalidArgumentException(sprintf(
                'The client "%s" registers redirection and login URIs on %s, so it registers a sector_identifier_uri to say which sector its subject identifiers belong to (OIDC Core section 8.1).',
                $registration->clientId,
                implode(' and ', array_keys($hosts)),
            ));
        }

        return new SectorIdentifier($registration->redirectUris[0]->host);
    }

    /**
     * OIDC Registration §5
     */
    public function publishedUris(ClientRegistration $registration): array
    {
        if (! $this->standsForTheSector($registration)) {
            return [];
        }
        $uris = array_map(static fn (RedirectUri $redirectUri): string => $redirectUri->value, $registration->redirectUris);
        if ($registration->initiateLoginUri !== null) {
            $uris[] = $registration->initiateLoginUri->value;
        }

        return $uris;
    }

    private function standsForTheSector(ClientRegistration $registration): bool
    {
        return $registration->redirectUris !== [] && ! $this->withoutARedirection->reach($registration);
    }
}

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
 * OIDC Core §8.1
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
     * OIDC Registration §5
     */
    public function publishedUris(ClientRegistration $registration): array
    {
        return array_map(
            static fn (RedirectUri $redirectUri): string => $redirectUri->value,
            $registration->redirectUris,
        );
    }
}

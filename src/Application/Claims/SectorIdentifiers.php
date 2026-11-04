<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Claims;

use function array_keys;
use Beffroi\Oidc\Domain\Claims\SectorIdentifier;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\SectorIdentifiersInterface;
use Beffroi\Oidc\Port\SectorIdentifierSourceInterface;
use function sprintf;

/**
 * OIDC Core §8.1, CIBA Core §4
 *
 * No fallback on purpose: a sector read from anything else would decide whom the client shares a user with.
 */
final readonly class SectorIdentifiers implements SectorIdentifiersInterface
{
    /**
     * @param iterable<SectorIdentifierSourceInterface> $sources in order of precedence
     */
    public function __construct(
        private iterable $sources,
    ) {
    }

    public function sectorOf(ClientRegistration $registration): SectorIdentifier
    {
        foreach ($this->sources as $source) {
            $sector = $source->sectorOf($registration);
            if ($sector !== null) {
                return $sector;
            }
        }

        throw new InvalidArgumentException(sprintf(
            'The client "%s" registers nothing that says which sector its subject identifiers belong to: a sector_identifier_uri, redirection URIs on one host (OIDC Core section 8.1), or, for a client that registers no redirection URI, a jwks_uri (CIBA Core section 4).',
            $registration->clientId,
        ));
    }

    /**
     * From every source, not only the one that answered: the document backs all the client could be judged on.
     *
     * @return list<string>
     */
    public function publishedUris(ClientRegistration $registration): array
    {
        $uris = [];
        foreach ($this->sources as $source) {
            foreach ($source->publishedUris($registration) as $uri) {
                $uris[$uri] = true;
            }
        }

        return array_keys($uris);
    }
}

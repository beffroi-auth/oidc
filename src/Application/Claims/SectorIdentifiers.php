<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Claims;

use function array_keys;
use Heidi\Oidc\Domain\Claims\SectorIdentifier;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Port\SectorIdentifiersInterface;
use Heidi\Oidc\Port\SectorIdentifierSourceInterface;
use function sprintf;

/**
 * The ways a client may say which sector it is of, in the order they are wired (OIDC Core §8.1, CIBA Core
 * §4). The one place the set of them is read, so that a source added later brings no rule with it and no
 * rule is written a second time.
 *
 * **The order is the answer.** The first source that reads a sector for a client is the one that decides,
 * which is how the URI a client registered to name its sector outranks what its other URIs would have
 * said. A source that says nothing of a client is passed over; a source that reads that client and finds
 * its registration names no one sector refuses there and then, because being unable to say is not the
 * same as having nothing to say.
 *
 * A client no wired source reads a sector for is refused rather than assigned one computed from something
 * else. There is no last resort here on purpose: whatever stood in would decide whom that client shares a
 * user with, and nobody asked for it.
 */
final readonly class SectorIdentifiers implements SectorIdentifiersInterface
{
    /**
     * @param iterable<SectorIdentifierSourceInterface> $sources the ways a client may say it, in the order they are wired
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
     * What every source reads of that client, and not only what the one that answered read: a document
     * that vouches for a client vouches for what that client would have been judged on wherever it is
     * read from.
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

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Claims\SectorIdentifier;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * One way a client says which sector it belongs to (OIDC Core §8.1, CIBA Core §4). A sector decides which
 * clients see a user under the same pairwise identifier, so where it is read from decides whom that client
 * shares a user with: it is read from what the client registered and from nothing else.
 *
 * **A source of more is a class and a line of wiring**, never a case added to something that knows how many
 * there are. §8.1 gives two, the URI the client registered to say so and the host of its redirection URIs;
 * CIBA Core §4 gives a third, the "jwks_uri" of a client that registers no redirection URI at all, and the
 * notification endpoint of push mode would be a fourth the day this provider served push.
 *
 * A source answers two things. Which sector it reads, and which URIs of the client it read that sector
 * from: the second is what the document of a registered sector must list (OIDC Registration §5), so that
 * what a client publishes to back its claim is what it would otherwise have been judged on.
 */
interface SectorIdentifierSourceInterface
{
    /**
     * @return SectorIdentifier|null null when this source says nothing about that client, which is what a
     *                               registration it reads nothing of looks like from here
     *
     * @throws InvalidArgumentException when this source reads that client and what it registered names no
     *                                  one sector
     */
    public function sectorOf(ClientRegistration $registration): ?SectorIdentifier;

    /**
     * @return list<string> the URIs of that client this source reads a sector from, as the client
     *                      registered them; empty for a source that reads none of it
     */
    public function publishedUris(ClientRegistration $registration): array;
}

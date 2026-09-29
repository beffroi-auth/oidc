<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Claims;

use Heidi\Oidc\Exception\InvalidArgumentException;
use Stringable;

/**
 * The Sector Identifier of a client (OIDC Core §8.1): the administrative domain a set of clients shares, and
 * the one thing a pairwise "sub" is computed per. Two clients of one sector see a user under one identifier;
 * two clients of two sectors cannot compare notes about them by comparing a string, which is what pairwise
 * identifiers exist for.
 *
 * It is a host and never a URL: §8.1 takes the host of the registered "sector_identifier_uri", and the host
 * of the redirection URIs when the client registered no such URI, which then must all be one host. A client
 * whose sector cannot be read from what it registered is refused rather than assigned an identifier computed
 * from something else, because what that something else was would decide whom it shares a user with.
 *
 * **Where it is read from is not here.** A sector is read from what a client registered, and which of the
 * things it registered says so is a class per source, wired and read in order (`SectorIdentifiersInterface`):
 * the URI it registered to say so, the host of its redirection URIs, and, for a client that registers none,
 * its "jwks_uri" (CIBA Core §4). This is the value they all answer with.
 */
final readonly class SectorIdentifier implements Stringable
{
    public function __construct(
        public string $host,
    ) {
        if ($host === '') {
            throw new InvalidArgumentException('A sector identifier is a host.');
        }
    }

    public function equals(self $other): bool
    {
        return $this->host === $other->host;
    }

    public function __toString(): string
    {
        return $this->host;
    }
}

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Claims;

use function array_keys;
use function count;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function implode;
use function sprintf;
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
 * A client that registers no redirection URI at all registers nothing this reads: CIBA Core §4 answers that
 * with the "jwks_uri" of the client, which is another source and a class of its own (issue #292).
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

    /**
     * OIDC Core §8.1, in the order the specification gives it: what the client registered to say so, then
     * what its redirection URIs say when they all say one thing.
     *
     * @throws InvalidArgumentException when what the client registered names no one sector
     */
    public static function of(ClientRegistration $registration): self
    {
        if ($registration->sectorIdentifierUri !== null) {
            return new self($registration->sectorIdentifierUri->host);
        }
        if ($registration->redirectUris === []) {
            throw new InvalidArgumentException(sprintf(
                'The client "%s" registers no redirection URI and no sector_identifier_uri, so nothing says which sector its subject identifiers belong to (OIDC Core section 8.1).',
                $registration->clientId,
            ));
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

        return new self($registration->redirectUris[0]->host);
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

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\SectorIdentifierUnavailableException;

/**
 * Reads back the document a client publishes behind its "sector_identifier_uri" (OIDC Registration §5): a
 * JSON array of the redirection URIs of the clients of that sector. One GET over HTTPS, no redirect followed
 * (decision 0006), a bounded body and a timeout of its own, as the keys of a client are read back
 * (ClientJwksFetcherInterface) and for the same reasons.
 *
 * What it proves is control: a client that claims a sector publishes, on that sector's own host, a document
 * naming the redirection URIs it registers. Nothing else makes a claimed sector anything but a string a
 * client wrote.
 */
interface SectorIdentifierDocumentFetcherInterface
{
    /**
     * @throws SectorIdentifierUnavailableException
     *
     * @return list<string> the redirection URIs the document lists, as it wrote them
     */
    public function fetch(ClientUri $sectorIdentifierUri): array;
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\SectorIdentifierUnavailableException;

/**
 * OIDC Registration §5
 *
 * One GET over HTTPS, no redirect followed (decision 0006), a bounded body and a timeout of its own.
 */
interface SectorIdentifierDocumentFetcherInterface
{
    /**
     * @throws SectorIdentifierUnavailableException
     *
     * @return list<string> the redirection URIs as the document wrote them
     */
    public function fetch(ClientUri $sectorIdentifierUri): array;
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Claims\SectorIdentifier;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Exception\InvalidArgumentException;

interface SectorIdentifiersInterface
{
    /**
     * @throws InvalidArgumentException when no wired source reads a sector for that client
     */
    public function sectorOf(ClientRegistration $registration): SectorIdentifier;

    /**
     * @return list<string> what the document of a registered sector must list (OIDC Registration §5)
     */
    public function publishedUris(ClientRegistration $registration): array;
}

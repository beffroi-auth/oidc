<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Claims\SectorIdentifier;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * OIDC Core §8.1, CIBA Core §4
 *
 * Read from what the client registered and nothing else: the sector decides whom the client shares a user with.
 */
interface SectorIdentifierSourceInterface
{
    /**
     * @throws InvalidArgumentException when what the client registered names no one sector
     */
    public function sectorOf(ClientRegistration $registration): ?SectorIdentifier;

    /**
     * @return list<string> the URIs it reads the sector from, as the client registered them
     */
    public function publishedUris(ClientRegistration $registration): array;
}

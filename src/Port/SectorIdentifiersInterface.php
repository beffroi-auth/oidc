<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Claims\SectorIdentifier;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Exception\InvalidArgumentException;

/**
 * The sector of a client, read through every source the deployment wired (OIDC Core §8.1, CIBA Core §4).
 * What a caller sees: one sector or a refusal, and never which source answered.
 *
 * It is the counterpart of `SectorIdentifierSourceInterface`, as `ServedGrantsInterface` is of
 * `GrantInterface`: a source says what it reads of one registration and may say nothing, and this says
 * what the set of them makes of a client. A client no wired source reads a sector for is refused rather
 * than assigned one computed from something else, because what that something else was would decide whom
 * it shares a user with.
 */
interface SectorIdentifiersInterface
{
    /**
     * @throws InvalidArgumentException when no wired source reads a sector for that client
     */
    public function sectorOf(ClientRegistration $registration): SectorIdentifier;

    /**
     * @return list<string> every URI of that client a wired source reads a sector from, which is what the
     *                      document of a registered sector must list (OIDC Registration §5, CIBA Core §4)
     */
    public function publishedUris(ClientRegistration $registration): array;
}

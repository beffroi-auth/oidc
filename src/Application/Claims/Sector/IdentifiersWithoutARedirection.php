<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Claims\Sector;

use function array_any;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * OIDC Core §8.1, CIBA Core §4
 *
 * Whether a grant the client is registered for hands it the identifiers of a person with no redirection to vouch for the
 * host it is reached on: one that asks the person on another device or through a backchannel.
 */
final readonly class IdentifiersWithoutARedirection
{
    public function __construct(
        private ServedGrantsInterface $grants,
    ) {
    }

    public function reach(ClientRegistration $registration): bool
    {
        return array_any(
            [...$this->grants->askingTheUserOnAnotherDevice(), ...$this->grants->askingTheUserThroughABackchannel()],
            static fn (GrantTypeName $grantType): bool => $registration->allowsGrant($grantType),
        );
    }
}

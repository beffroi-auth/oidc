<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Flow;

use Beffroi\Oidc\Domain\Flow\TokenEndpointHops;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * The flow of a grant a client uses for itself, with nobody signed in behind it (RFC 6749 §4.4): it
 * opens at the token endpoint and there is no browser in it at all, which is the whole of what tells
 * this picture from the one of a flow that has a user.
 */
final readonly class TheClientActsForItself implements FlowShapeInterface
{
    public function grantTypes(ServedGrantsInterface $served): array
    {
        return $served->actingForTheClientItself();
    }

    public function hops(): array
    {
        return TokenEndpointHops::askedAndAnswered('RFC 6749 §4.4.2', 'RFC 6749 §4.4.3');
    }
}

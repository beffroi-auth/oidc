<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Flow;

use function array_merge;
use Beffroi\Oidc\Domain\Client\GrantTypesApart;
use Beffroi\Oidc\Domain\Flow\TokenEndpointHops;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * RFC 6749 §4.5
 */
final readonly class TheClientAsksForATokenAlone implements FlowShapeInterface
{
    public function grantTypes(ServedGrantsInterface $served): array
    {
        return GrantTypesApart::of($served->servedGrantTypes(), array_merge(
            $served->sendingTheUserToTheClient(),
            $served->askingTheUserOnAnotherDevice(),
            $served->askingTheUserThroughABackchannel(),
            $served->actingForTheClientItself(),
        ));
    }

    public function hops(): array
    {
        return TokenEndpointHops::askedAndAnswered('RFC 6749 §3.2', 'RFC 6749 §5.1');
    }
}

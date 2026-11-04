<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Flow;

use Beffroi\Oidc\Domain\Flow\TokenEndpointHops;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * RFC 6749 §4.4
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

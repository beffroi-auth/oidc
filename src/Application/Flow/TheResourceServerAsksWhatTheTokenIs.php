<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Flow;

use Beffroi\Oidc\Domain\Flow\Actor;
use Beffroi\Oidc\Domain\Flow\Hop;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * RFC 7662 §2
 */
final readonly class TheResourceServerAsksWhatTheTokenIs implements FlowShapeInterface
{
    public const string INTROSPECTION_REQUEST = 'introspection_request';

    public const string INTROSPECTION_RESPONSE = 'introspection_response';

    public function grantTypes(ServedGrantsInterface $served): array
    {
        return $served->servedGrantTypes();
    }

    public function hops(): array
    {
        return [
            new Hop(Actor::ResourceServer, Actor::Provider, self::INTROSPECTION_REQUEST, 'RFC 7662 §2.1'),
            new Hop(Actor::Provider, Actor::ResourceServer, self::INTROSPECTION_RESPONSE, 'RFC 7662 §2.2'),
        ];
    }
}

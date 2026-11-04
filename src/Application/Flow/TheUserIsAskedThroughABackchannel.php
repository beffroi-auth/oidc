<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Flow;

use Beffroi\Oidc\Domain\Flow\Actor;
use Beffroi\Oidc\Domain\Flow\Hop;
use Beffroi\Oidc\Domain\Flow\TokenEndpointHops;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * CIBA Core §7
 */
final readonly class TheUserIsAskedThroughABackchannel implements FlowShapeInterface
{
    public const string BACKCHANNEL_AUTHENTICATION_REQUEST = 'backchannel_authentication_request';

    public const string BACKCHANNEL_AUTHENTICATION_RESPONSE = 'backchannel_authentication_response';

    public const string APPROVAL = 'approval';

    public const string NOTIFICATION = 'notification';

    public function grantTypes(ServedGrantsInterface $served): array
    {
        return $served->askingTheUserThroughABackchannel();
    }

    public function hops(): array
    {
        return [
            new Hop(Actor::Client, Actor::Provider, self::BACKCHANNEL_AUTHENTICATION_REQUEST, 'CIBA Core §7'),
            new Hop(Actor::Provider, Actor::Client, self::BACKCHANNEL_AUTHENTICATION_RESPONSE, 'CIBA Core §7.3'),
            new Hop(Actor::Browser, Actor::Provider, self::APPROVAL, 'CIBA Core §7.1'),
            new Hop(Actor::Provider, Actor::Client, self::NOTIFICATION, 'CIBA Core §10.2'),
            ...TokenEndpointHops::askedAndAnswered('CIBA Core §10.1', 'CIBA Core §10.1.1', true),
        ];
    }
}

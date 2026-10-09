<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Flow;

use Beffroi\Oidc\Domain\Flow\Actor;
use Beffroi\Oidc\Domain\Flow\Hop;
use Beffroi\Oidc\Domain\Flow\TokenEndpointHops;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * The flow of a grant whose user this provider reaches itself, on a device they already hold (CIBA
 * Core §7): the client names the user it is asking for and waits, and the browser it never sees is the
 * one this provider went looking for.
 *
 * The notification is the hop a client registered for the ping or the push mode is told by, and the one
 * a client that polls never gets (§10.2): it is a hop of this flow whatever the mode, drawn as a hop a
 * run did not take when the client of that run polls.
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

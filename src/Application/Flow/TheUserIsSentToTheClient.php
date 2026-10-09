<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Flow;

use Beffroi\Oidc\Domain\Flow\Actor;
use Beffroi\Oidc\Domain\Flow\Hop;
use Beffroi\Oidc\Domain\Flow\TokenEndpointHops;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * The flow of a grant that sends the user's browser back to the client (RFC 6749 §4.1): the browser
 * carries the request to this provider, carries the response back, and the client then spends what it
 * was given at the token endpoint, server to server, where no browser goes.
 *
 * Four hops and no more: the client building the request and the browser landing at the redirect URI
 * carry the same two payloads as the hops below, and a drawing that showed them twice would say the
 * flow exchanged twice what it exchanged once.
 */
final readonly class TheUserIsSentToTheClient implements FlowShapeInterface
{
    public const string AUTHORIZATION_REQUEST = 'authorization_request';

    public const string AUTHORIZATION_RESPONSE = 'authorization_response';

    public function grantTypes(ServedGrantsInterface $served): array
    {
        return $served->sendingTheUserToTheClient();
    }

    public function hops(): array
    {
        return [
            new Hop(Actor::Browser, Actor::Provider, self::AUTHORIZATION_REQUEST, 'RFC 6749 §4.1.1'),
            new Hop(Actor::Provider, Actor::Browser, self::AUTHORIZATION_RESPONSE, 'RFC 6749 §4.1.2'),
            ...TokenEndpointHops::askedAndAnswered('RFC 6749 §4.1.3', 'RFC 6749 §4.1.4'),
        ];
    }
}

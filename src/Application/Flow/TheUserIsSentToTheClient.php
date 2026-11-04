<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Flow;

use Beffroi\Oidc\Domain\Flow\Actor;
use Beffroi\Oidc\Domain\Flow\Hop;
use Beffroi\Oidc\Domain\Flow\TokenEndpointHops;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * RFC 6749 §4.1
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

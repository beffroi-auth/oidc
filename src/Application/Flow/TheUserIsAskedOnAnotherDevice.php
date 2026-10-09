<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Flow;

use Beffroi\Oidc\Domain\Flow\Actor;
use Beffroi\Oidc\Domain\Flow\Hop;
use Beffroi\Oidc\Domain\Flow\TokenEndpointHops;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * The flow of a grant whose user is asked somewhere other than in the client's own browser (RFC 8628):
 * the client has no browser to send anywhere, so it starts the flow at an endpoint of its own, shows
 * what it was answered, and asks the token endpoint again and again while the user types that code on
 * another screen.
 *
 * The code travelling from the client's screen to the user is the one step of this flow that is not an
 * exchange of the protocol: nothing is sent, somebody reads. It is drawn by the hop the user then makes,
 * which is the first thing this provider sees of them (§3.3).
 */
final readonly class TheUserIsAskedOnAnotherDevice implements FlowShapeInterface
{
    public const string DEVICE_AUTHORIZATION_REQUEST = 'device_authorization_request';

    public const string DEVICE_AUTHORIZATION_RESPONSE = 'device_authorization_response';

    public const string USER_CODE = 'user_code';

    public function grantTypes(ServedGrantsInterface $served): array
    {
        return $served->askingTheUserOnAnotherDevice();
    }

    public function hops(): array
    {
        return [
            new Hop(Actor::Client, Actor::Provider, self::DEVICE_AUTHORIZATION_REQUEST, 'RFC 8628 §3.1'),
            new Hop(Actor::Provider, Actor::Client, self::DEVICE_AUTHORIZATION_RESPONSE, 'RFC 8628 §3.2'),
            new Hop(Actor::Browser, Actor::Provider, self::USER_CODE, 'RFC 8628 §3.3'),
            ...TokenEndpointHops::askedAndAnswered('RFC 8628 §3.4', 'RFC 8628 §3.5', true),
        ];
    }
}

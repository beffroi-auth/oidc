<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Flow;

use Beffroi\Oidc\Domain\Flow\Actor;
use Beffroi\Oidc\Domain\Flow\Hop;
use Beffroi\Oidc\Domain\Flow\TokenEndpointHops;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * RFC 8628
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

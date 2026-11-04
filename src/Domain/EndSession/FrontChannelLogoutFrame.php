<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\EndSession;

use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Exception\LogicException;
use function sprintf;

/**
 * Front-Channel Logout 1.0 §2
 */
final readonly class FrontChannelLogoutFrame
{
    private function __construct(
        public string $clientId,
        public string $uri,
        public string $origin,
    ) {
    }

    /**
     * @throws LogicException for a client that registered no front-channel logout URI
     */
    public static function ofSession(Client $client, AuthenticationSession $session): self
    {
        $registered = $client->registration->frontChannelLogoutUri ?? throw new LogicException(sprintf(
            'The client "%s" registered no front-channel logout URI and is not loaded by the logout page.',
            $client->registration->clientId,
        ));
        $uri = $client->registration->frontChannelLogoutSessionRequired
            ? $registered->withParameters([
                'iss' => (string) $session->tenant->issuer,
                'sid' => $session->id->toRfc4122(),
            ]) : $registered->value;

        return new self($client->registration->clientId, $uri, $registered->origin);
    }
}

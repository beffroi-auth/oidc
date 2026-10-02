<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Method;

use Beffroi\Oidc\Application\Client\ClientAuthenticationRequest;
use Beffroi\Oidc\Domain\Client\Client;

/**
 * "none" (RFC 6749 §2.1, OIDC Core §9): a public client names itself and proves nothing. It is not an
 * authentication and it is announced as what it is; what protects the grant of such a client is PKCE and
 * the exact redirect URI, never this method.
 */
final readonly class NoAuthentication implements AuthenticationMethodInterface
{
    public function name(): string
    {
        return 'none';
    }

    public function mechanism(): string
    {
        return 'the client_id parameter';
    }

    public function authenticatesClient(): bool
    {
        return false;
    }

    public function presentedBy(ClientAuthenticationRequest $request): ?string
    {
        return $request->clientId();
    }

    public function verify(ClientAuthenticationRequest $request, Client $client): void
    {
    }

    /**
     * Nothing was presented, so nothing is paid: a request that carries no secret cannot be timed against
     * one that does.
     */
    public function payRefusal(ClientAuthenticationRequest $request): void
    {
    }
}

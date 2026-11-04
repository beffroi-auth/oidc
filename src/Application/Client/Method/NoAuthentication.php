<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Method;

use Beffroi\Oidc\Application\Client\ClientAuthenticationRequest;
use Beffroi\Oidc\Domain\Client\Client;

/**
 * RFC 6749 §2.1, OIDC Core §9
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

    public function payRefusal(ClientAuthenticationRequest $request): void
    {
    }
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Method;

use Beffroi\Core\Application\Authentication\DecoyHash;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Oidc\Application\Client\ClientAuthenticationFailure;
use Beffroi\Oidc\Application\Client\ClientAuthenticationRequest;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientSecretInterface;
use Beffroi\Oidc\Domain\Client\HashedClientSecret;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Beffroi\Oidc\Exception\ClientNotAuthenticatedHereException;
use SensitiveParameter;

/**
 * RFC 6749 §2.3.1
 */
abstract readonly class HashedSecretMethod implements AuthenticationMethodInterface, SecretKeepingMethodInterface
{
    public function __construct(
        private PasswordHasherInterface $hasher,
        private DecoyHash $decoy,
    ) {
    }

    public function authenticatesClient(): bool
    {
        return true;
    }

    public function keep(#[SensitiveParameter] string $secret, PasswordHasherInterface $hasher): ClientSecretInterface
    {
        return new HashedClientSecret($hasher->hash($secret));
    }

    public function accepts(ClientSecretInterface $secret): bool
    {
        return $secret instanceof HashedClientSecret;
    }

    public function holdsSecret(#[SensitiveParameter] string $presented, ClientSecretInterface $kept): bool
    {
        return $kept instanceof HashedClientSecret && $this->hasher->verify($kept->hash, $presented);
    }

    /**
     * @throws ClientNotAuthenticatedHereException when no secret is read or the client's is in another shape
     * @throws ClientAuthenticationFailure
     */
    public function verify(ClientAuthenticationRequest $request, Client $client): void
    {
        $presented = $this->presentedSecret($request);
        $secret = $client->secret;
        if ($presented === null || ! $secret instanceof HashedClientSecret) {
            throw new ClientNotAuthenticatedHereException($client, $this);
        }
        if (! $this->hasher->verify($secret->hash, $presented)) {
            throw ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::InvalidSecret, $client->registration->clientId, $this->name());
        }
    }

    public function payRefusal(ClientAuthenticationRequest $request): void
    {
        $presented = $this->presentedSecret($request);
        if ($presented !== null) {
            $this->decoy->verify($presented);
        }
    }

    abstract protected function presentedSecret(ClientAuthenticationRequest $request): ?string;
}

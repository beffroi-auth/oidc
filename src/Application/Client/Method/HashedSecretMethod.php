<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Method;

use Heidi\Core\Application\Authentication\DecoyHash;
use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Oidc\Application\Client\ClientAuthenticationFailure;
use Heidi\Oidc\Application\Client\ClientAuthenticationRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientSecretInterface;
use Heidi\Oidc\Domain\Client\HashedClientSecret;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Heidi\Oidc\Exception\ClientNotAuthenticatedHereException;
use SensitiveParameter;

/**
 * A method whose client proves a shared secret the provider keeps as a hash (RFC 6749 §2.3.1). What such
 * a method does with the secret is the same whichever way the request carries it: the provider keeps a
 * hash it can verify against and never the secret, a refusal costs what an acceptance costs, and a
 * client kept in another shape is a fault of the wiring.
 *
 * Where the request carries the secret is the one thing that differs, and it is the one thing a kind
 * says for itself. Adding a third way of presenting a shared secret is a class that answers two
 * questions, not a third copy of this one.
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

    /**
     * @throws ClientNotAuthenticatedHereException when the request no longer carries the secret the
     *                                                authenticator read, or when the client is kept in a
     *                                                shape this method does not verify
     * @throws ClientAuthenticationFailure when the secret presented is not the one registered
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

    /**
     * A refusal costs what an acceptance costs, so that the time a request takes tells nothing about
     * whether the client is registered (architecture §7).
     */
    public function payRefusal(ClientAuthenticationRequest $request): void
    {
        $presented = $this->presentedSecret($request);
        if ($presented !== null) {
            $this->decoy->verify($presented);
        }
    }

    /**
     * The secret this request carries under this method, null when it carries none.
     */
    abstract protected function presentedSecret(ClientAuthenticationRequest $request): ?string;
}

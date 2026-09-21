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
use Heidi\Oidc\Exception\LogicException;
use SensitiveParameter;
use function sprintf;

/**
 * "client_secret_post" (RFC 6749 §2.3.1): the identifier and the secret in the request body. The
 * specification only allows it for clients that cannot use the Authorization header, and the provider
 * takes it from the clients that registered it and from no other.
 */
final readonly class ClientSecretPost implements SecretKeepingMethodInterface, AuthenticationMethodInterface
{
    public function __construct(
        private PasswordHasherInterface $hasher,
        private DecoyHash $decoy,
    ) {
    }

    public function name(): string
    {
        return 'client_secret_post';
    }

    public function mechanism(): string
    {
        return ClientAuthenticationRequest::BODY_SECRET;
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

    public function presentedBy(ClientAuthenticationRequest $request): ?string
    {
        if ($request->secret() === null) {
            return null;
        }
        $clientId = $request->clientId();
        if ($clientId === null) {
            throw ClientAuthenticationFailure::malformedRequest(ClientAuthenticationFailureReason::MalformedCredentials, null, $this->name(), 'The client_secret parameter requires a client_id parameter.');
        }

        return $clientId;
    }

    public function verify(ClientAuthenticationRequest $request, Client $client): void
    {
        $presented = $request->secret();
        $secret = $client->secret;
        if ($presented === null || ! $secret instanceof HashedClientSecret) {
            throw new LogicException(sprintf('The client "%s" is not authenticated by %s here.', $client->clientId, $this->name()));
        }
        if (! $this->hasher->verify($secret->hash, $presented)) {
            throw ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::InvalidSecret, $client->clientId, $this->name());
        }
    }

    public function payRefusal(ClientAuthenticationRequest $request): void
    {
        $presented = $request->secret();
        if ($presented !== null) {
            $this->decoy->verify($presented);
        }
    }
}

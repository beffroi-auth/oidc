<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Method;

use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Oidc\Application\Client\ClientAssertionValidator;
use Heidi\Oidc\Application\Client\ClientAuthenticationFailure;
use Heidi\Oidc\Application\Client\ClientAuthenticationRequest;
use Heidi\Oidc\Domain\Client\AssertionMethodInterface;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientSecretInterface;
use Heidi\Oidc\Domain\Client\SharedClientSecret;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Heidi\Oidc\Exception\InvalidClientAssertionException;
use Heidi\Oidc\Exception\LogicException;
use Heidi\Oidc\Port\ClientAssertionReaderInterface;
use Heidi\Oidc\Port\ClientAssertionSecretVerifierInterface;
use function in_array;
use SensitiveParameter;
use function sprintf;

/**
 * "client_secret_jwt" (OIDC Core §9): the same assertion as "private_key_jwt", signed with the secret
 * the client registered instead of a key of its own, HS256 and nothing else (RFC 8725 §3.1, §3.2). It is
 * served because clients ask for it, and it is not a FAPI method: the provider has to hold the secret
 * back to compute the same MAC, which is what FAPI 2.0 §5.2.2 refuses. A deployment that follows the
 * profile leaves the method out of its wiring, and then no client can register it and the discovery
 * document does not announce it.
 */
final readonly class ClientSecretJwt implements AssertionMethodInterface, SecretKeepingMethodInterface, AuthenticationMethodInterface
{
    /**
     * OIDC Core §9 allows HS256, HS384 and HS512; one is enough and is what clients send.
     */
    private const string ALGORITHM = 'HS256';

    public function __construct(
        private ClientAssertionReaderInterface $reader,
        private ClientAssertionSecretVerifierInterface $verifier,
        private ClientAssertionValidator $claims,
    ) {
    }

    public function name(): string
    {
        return 'client_secret_jwt';
    }

    public function authenticatesClient(): bool
    {
        return true;
    }

    public function assertionSigningAlgorithms(): array
    {
        return [self::ALGORITHM];
    }

    public function keep(#[SensitiveParameter] string $secret, PasswordHasherInterface $hasher): ClientSecretInterface
    {
        return new SharedClientSecret($secret);
    }

    public function accepts(ClientSecretInterface $secret): bool
    {
        return $secret instanceof SharedClientSecret;
    }

    public function presentedBy(ClientAuthenticationRequest $request): ?string
    {
        $assertion = $request->assertion($this->reader);
        if ($assertion === null || ! in_array($assertion->algorithm(), $this->assertionSigningAlgorithms(), true)) {
            return null;
        }

        return $request->assertedClientId($assertion);
    }

    public function verify(ClientAuthenticationRequest $request, Client $client): void
    {
        $assertion = $request->assertion($this->reader);
        $secret = $client->secret;
        if ($assertion === null || ! $secret instanceof SharedClientSecret) {
            throw new LogicException(sprintf('The client "%s" is not authenticated by %s here.', $client->clientId, $this->name()));
        }
        try {
            $this->verifier->verify($assertion, $secret, $this->assertionSigningAlgorithms());
        } catch (InvalidClientAssertionException $exception) {
            throw ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::InvalidAssertion, $client->clientId, $this->name(), $exception->getMessage(), $exception);
        }
        $this->claims->validate($this, $assertion, $client, $request);
    }

    /**
     * A MAC over a secret nobody registered cannot be computed, and computing one over a decoy would
     * measure nothing: the secret is never shown to the provider here, so a refusal has nothing to pay.
     */
    public function payRefusal(ClientAuthenticationRequest $request): void
    {
    }
}

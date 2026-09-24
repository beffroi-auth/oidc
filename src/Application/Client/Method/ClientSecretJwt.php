<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Method;

use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Oidc\Application\Client\ClientAssertionValidator;
use Heidi\Oidc\Application\Client\ClientAuthenticationRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientSecretInterface;
use Heidi\Oidc\Domain\Client\SharedClientSecret;
use Heidi\Oidc\Domain\Token\UnverifiedJwt;
use Heidi\Oidc\Port\ClientAssertionSecretVerifierInterface;
use Heidi\Oidc\Port\CompactJwtReaderInterface;
use SensitiveParameter;

/**
 * "client_secret_jwt" (OIDC Core §9): the same assertion as "private_key_jwt", signed with the secret
 * the client registered instead of a key of its own, HS256 and nothing else (RFC 8725 §3.1, §3.2). It is
 * served because clients ask for it, and it is not a FAPI method: the provider has to hold the secret
 * back to compute the same MAC, which is what FAPI 2.0 §5.2.2 refuses. A deployment that follows the
 * profile leaves the method out of its wiring, and then no client can register it and the discovery
 * document does not announce it.
 */
final readonly class ClientSecretJwt extends AssertionMethod implements SecretKeepingMethodInterface
{
    /**
     * OIDC Core §9 allows HS256, HS384 and HS512; one is enough and is what clients send.
     */
    private const string ALGORITHM = 'HS256';

    public function __construct(
        CompactJwtReaderInterface $reader,
        private ClientAssertionSecretVerifierInterface $verifier,
        ClientAssertionValidator $claims,
    ) {
        parent::__construct($reader, $claims);
    }

    public function name(): string
    {
        return 'client_secret_jwt';
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

    protected function verifySignature(UnverifiedJwt $assertion, Client $client): void
    {
        $secret = $client->secret;
        if (! $secret instanceof SharedClientSecret) {
            throw ClientAuthenticationRequest::notAuthenticatedHere($client, $this);
        }
        $this->verifier->verify($assertion, $secret, $this->assertionSigningAlgorithms());
    }
}

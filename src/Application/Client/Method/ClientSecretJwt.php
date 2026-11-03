<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Method;

use function hash_equals;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Oidc\Application\Client\ClientAssertionValidator;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientSecretInterface;
use Beffroi\Oidc\Domain\Client\SharedClientSecret;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\ClientNotAuthenticatedHereException;
use Beffroi\Oidc\Port\ClientAssertionSecretVerifierInterface;
use SensitiveParameter;

/**
 * "client_secret_jwt" (OIDC Core §9): the same assertion as "private_key_jwt", signed with the secret
 * the client registered instead of a key of its own, HS256 and nothing else (RFC 8725 §3.1, §3.2). It is
 * served because clients ask for it, and it is not a FAPI method: the provider has to hold the secret
 * back to compute the same MAC, and FAPI 2.0 Security Profile §5.3.2.1 takes MTLS and private_key_jwt
 * alone. A deployment that follows the profile leaves the method out of its wiring, and then no client
 * can register it and the discovery document does not announce it.
 */
final readonly class ClientSecretJwt extends AssertionMethod implements SecretKeepingMethodInterface
{
    /**
     * OIDC Core §9 allows HS256, HS384 and HS512; one is enough and is what clients send.
     */
    private const string ALGORITHM = 'HS256';

    public function __construct(
        private ClientAssertionSecretVerifierInterface $verifier,
        ClientAssertionValidator $claims,
    ) {
        parent::__construct($claims);
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

    public function holdsSecret(#[SensitiveParameter] string $presented, ClientSecretInterface $kept): bool
    {
        return $kept instanceof SharedClientSecret && hash_equals($kept->value, $presented);
    }

    protected function verifySignature(UnverifiedJwt $assertion, Client $client): void
    {
        $secret = $client->secret;
        if (! $secret instanceof SharedClientSecret) {
            throw new ClientNotAuthenticatedHereException($client, $this);
        }
        $this->verifier->verify($assertion, $secret, $this->assertionSigningAlgorithms());
    }
}

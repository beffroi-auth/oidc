<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Method;

use function array_map;
use Heidi\Core\Domain\Key\SignatureAlgorithmInterface;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Oidc\Application\Client\ClientAssertionValidator;
use Heidi\Oidc\Application\Client\ClientAuthenticationFailure;
use Heidi\Oidc\Application\Client\ClientAuthenticationRequest;
use Heidi\Oidc\Application\Client\ClientKeySetProvider;
use Heidi\Oidc\Domain\Client\AssertionMethodInterface;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\KeyBearingMethodInterface;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Heidi\Oidc\Exception\ClientKeysUnavailableException;
use Heidi\Oidc\Exception\InvalidClientAssertionException;
use Heidi\Oidc\Port\ClientAssertionKeyVerifierInterface;
use Heidi\Oidc\Port\ClientAssertionReaderInterface;
use function in_array;

/**
 * "private_key_jwt" (OIDC Core §9, RFC 7523 §2.2): the client signs a JWT with a key of its own and the
 * provider verifies it against the keys the client publishes. One of the two ways FAPI 2.0 §5.2.2
 * accepts, and the only one that needs no secret at rest on either side.
 *
 * What an assertion may be signed with is what the provider is wired with (issue #156): a deployment
 * that follows FAPI 2 drops the RS256 line of its wiring and the method refuses RS256 with it, the
 * discovery document saying so in "token_endpoint_auth_signing_alg_values_supported".
 */
final readonly class PrivateKeyJwt implements AssertionMethodInterface, KeyBearingMethodInterface, AuthenticationMethodInterface
{
    public function __construct(
        private ClientAssertionReaderInterface $reader,
        private ClientAssertionKeyVerifierInterface $verifier,
        private ClientKeySetProvider $keys,
        private ClientAssertionValidator $claims,
        private SignatureAlgorithmsInterface $algorithms,
    ) {
    }

    public function name(): string
    {
        return 'private_key_jwt';
    }

    public function mechanism(): string
    {
        return ClientAuthenticationRequest::ASSERTION;
    }

    public function authenticatesClient(): bool
    {
        return true;
    }

    public function assertionSigningAlgorithms(): array
    {
        return array_map(static fn (SignatureAlgorithmInterface $algorithm): string => $algorithm->name(), $this->algorithms->all());
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
        if ($assertion === null) {
            throw ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::InvalidAssertion, $client->clientId, $this->name(), 'the request carries no client assertion');
        }
        try {
            $keys = $this->keys->keysOf($client, $assertion->keyId());
        } catch (ClientKeysUnavailableException $exception) {
            throw ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::UnreadableClientKeys, $client->clientId, $this->name(), $exception->getMessage(), $exception);
        }
        try {
            $this->verifier->verify($assertion, $keys, $this->assertionSigningAlgorithms());
        } catch (InvalidClientAssertionException $exception) {
            throw ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::InvalidAssertion, $client->clientId, $this->name(), $exception->getMessage(), $exception);
        }
        $this->claims->validate($this, $assertion, $client, $request);
    }

    /**
     * An assertion is verified against a key, not against a decoy: there is no secret to compare and
     * nothing to make constant.
     */
    public function payRefusal(ClientAuthenticationRequest $request): void
    {
    }
}

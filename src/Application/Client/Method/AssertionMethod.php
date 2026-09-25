<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Method;

use Heidi\Oidc\Application\Client\ClientAssertionValidator;
use Heidi\Oidc\Application\Client\ClientAuthenticationFailure;
use Heidi\Oidc\Application\Client\ClientAuthenticationRequest;
use Heidi\Oidc\Domain\Client\AssertionMethodInterface;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Heidi\Oidc\Domain\Token\UnverifiedJwt;
use Heidi\Oidc\Exception\ClientNotAuthenticatedHereException;
use Heidi\Oidc\Exception\InvalidJwtException;
use function in_array;

/**
 * A method whose client proves itself with a JWT it signs (RFC 7523 §2.2, OIDC Core §9). What such a
 * method does with the assertion is the same whatever signed it: the request presents this method when
 * it carries an assertion under an "alg" the method takes, the assertion names the client in its "sub",
 * the signature is verified, and the claims are judged by the validator every assertion goes through.
 *
 * What the signature is verified against is the one thing that differs, a key the client publishes or
 * the secret it registered, and it is the one thing a kind says for itself. A third way of signing an
 * assertion is a class that answers that one question, not a third copy of this one.
 */
abstract readonly class AssertionMethod implements AssertionMethodInterface, AuthenticationMethodInterface
{
    public function __construct(
        private ClientAssertionValidator $claims,
    ) {
    }

    public function mechanism(): string
    {
        return 'the client_assertion parameter';
    }

    public function authenticatesClient(): bool
    {
        return true;
    }

    /**
     * RFC 7523 §3: the assertion names the client in its "sub", and the "client_id" of the body names it
     * too when the client sends both; whether the two agree is judged once the signature has been. A
     * request carrying an assertion signed under an "alg" this method does not take presents another
     * method, or none.
     *
     * @throws ClientAuthenticationFailure when neither names a client, and there is nothing to look up
     */
    public function presentedBy(ClientAuthenticationRequest $request): ?string
    {
        $assertion = $request->assertion;
        if ($assertion === null || ! in_array($assertion->algorithm(), $this->assertionSigningAlgorithms(), true)) {
            return null;
        }

        return (
            $assertion->claim('sub')
            ?? $request->clientId()
            ?? throw ClientAuthenticationFailure::refused(
                ClientAuthenticationFailureReason::InvalidAssertion,
                null,
                null,
                'the client assertion names no client in its "sub"',
            )
        );
    }

    /**
     * @throws ClientNotAuthenticatedHereException when the request no longer carries the assertion the authenticator read
     * @throws ClientAuthenticationFailure when the assertion is not the client's
     */
    public function verify(ClientAuthenticationRequest $request, Client $client): void
    {
        $assertion = $request->assertion;
        if ($assertion === null) {
            throw new ClientNotAuthenticatedHereException($client, $this);
        }
        try {
            $this->verifySignature($assertion, $client);
        } catch (InvalidJwtException $exception) {
            throw ClientAuthenticationFailure::refused(
                ClientAuthenticationFailureReason::InvalidAssertion,
                $client->registration->clientId,
                $this->name(),
                $exception->getMessage(),
                $exception,
            );
        }
        $this->claims->validate($this, $assertion, $client, $request);
    }

    /**
     * An assertion is verified against something the client published or something only it and the
     * provider know, never against a value the request shows: there is no secret here whose comparison
     * has to be made constant, and a decoy would measure nothing.
     */
    public function payRefusal(ClientAuthenticationRequest $request): void
    {
    }

    /**
     * Whether the assertion carries the signature of this client, which is the whole of what tells one
     * kind of assertion from another.
     *
     * @throws ClientNotAuthenticatedHereException when the client is kept in a shape this method does not verify
     * @throws InvalidJwtException when the signature is not the client's
     */
    abstract protected function verifySignature(UnverifiedJwt $assertion, Client $client): void;
}

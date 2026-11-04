<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Method;

use Beffroi\Oidc\Application\Client\ClientAssertionValidator;
use Beffroi\Oidc\Application\Client\ClientAuthenticationFailure;
use Beffroi\Oidc\Application\Client\ClientAuthenticationRequest;
use Beffroi\Oidc\Domain\Client\AssertionMethodInterface;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\ClientNotAuthenticatedHereException;
use Beffroi\Oidc\Exception\InvalidJwtException;
use function in_array;

/**
 * RFC 7523 §2.2, OIDC Core §9
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
     * RFC 7523 §3
     *
     * @throws ClientAuthenticationFailure when neither "sub" nor "client_id" names a client
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
     * @throws ClientNotAuthenticatedHereException when the request no longer carries the assertion
     * @throws ClientAuthenticationFailure
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
     * Nothing to pay: no secret the request shows is compared here, so a decoy would measure nothing.
     */
    public function payRefusal(ClientAuthenticationRequest $request): void
    {
    }

    /**
     * @throws ClientNotAuthenticatedHereException when the client is kept in a shape this method does not verify
     * @throws InvalidJwtException
     */
    abstract protected function verifySignature(UnverifiedJwt $assertion, Client $client): void;
}

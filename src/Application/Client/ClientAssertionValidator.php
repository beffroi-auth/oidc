<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client;

use DateInterval;
use DateTimeImmutable;
use Heidi\Oidc\Domain\Client\AssertionMethodInterface;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Heidi\Oidc\Domain\Token\UnverifiedJwt;
use Heidi\Oidc\Port\ClientAssertionReplayGuardInterface;
use function in_array;

/**
 * What a client assertion has to say once its signature has been verified (RFC 7523 §3, OIDC Core §9),
 * the same for every method that carries one. "iss" and "sub" both name the client, so an assertion
 * cannot be presented for another one. "aud" names the endpoint that received the request, or the issuer
 * of the tenant: OIDC Core §9 says the token endpoint URL and RFC 7523 §3 says an identifier of the
 * authorization server, and both are in use in the field. "exp" is there and is bounded, so that an
 * assertion is not a bearer token for a year. "jti" is there and is remembered until "exp", so that an
 * assertion authenticates once.
 */
final readonly class ClientAssertionValidator
{
    /**
     * @param DateInterval $maximumLifetime how far ahead of the request an "exp" may be
     * @param DateInterval $leeway what is allowed of the clock of the client, both ways
     */
    public function __construct(
        private ClientAssertionReplayGuardInterface $replays,
        private DateInterval $maximumLifetime,
        private DateInterval $leeway,
    ) {
    }

    /**
     * @param AssertionMethodInterface $method the method the assertion was presented under, which the
     *                                         audit trail records with the refusal
     *
     * @throws ClientAuthenticationFailure
     */
    public function validate(AssertionMethodInterface $method, UnverifiedJwt $assertion, Client $client, ClientAuthenticationRequest $request): void
    {
        $clientId = $client->clientId;
        if ($assertion->claim('iss') !== $clientId || $assertion->claim('sub') !== $clientId) {
            throw $this->refuse($method, $clientId, 'the "iss" and the "sub" of a client assertion both name the client (RFC 7523 section 3)');
        }
        $audiences = $assertion->audiences();
        if (! in_array($request->endpoint, $audiences, true) && ! in_array($request->tenant->issuer->value, $audiences, true)) {
            throw $this->refuse($method, $clientId, 'the "aud" of a client assertion names the endpoint it is sent to or the issuer of the provider (RFC 7523 section 3)');
        }
        $now = $request->context->receivedAt;
        $expiresAt = $assertion->time('exp');
        if ($expiresAt === null) {
            throw $this->refuse($method, $clientId, 'a client assertion carries an "exp" (RFC 7523 section 3)');
        }
        if ($expiresAt <= $now->sub($this->leeway)) {
            throw $this->refuse($method, $clientId, 'the client assertion has expired');
        }
        if ($expiresAt > $now->add($this->leeway)->add($this->maximumLifetime)) {
            throw $this->refuse($method, $clientId, 'the "exp" of a client assertion stays inside the lifetime this provider accepts');
        }
        $issuedAt = $assertion->time('iat');
        if ($issuedAt === null) {
            throw $this->refuse($method, $clientId, 'a client assertion carries an "iat"');
        }
        if ($issuedAt > $now->add($this->leeway)) {
            throw $this->refuse($method, $clientId, 'the client assertion is issued in the future');
        }
        $this->rememberOnce($method, $assertion, $client, $expiresAt);
    }

    /**
     * @throws ClientAuthenticationFailure
     */
    private function rememberOnce(AssertionMethodInterface $method, UnverifiedJwt $assertion, Client $client, DateTimeImmutable $expiresAt): void
    {
        $jti = $assertion->claim('jti');
        if ($jti === null) {
            throw $this->refuse($method, $client->clientId, 'a client assertion carries a "jti"');
        }
        if (! $this->replays->remember($client, $jti, $expiresAt)) {
            throw ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::ReplayedAssertion, $client->clientId, $method->name());
        }
    }

    private function refuse(AssertionMethodInterface $method, string $clientId, string $reason): ClientAuthenticationFailure
    {
        return ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::InvalidAssertion, $clientId, $method->name(), $reason);
    }
}

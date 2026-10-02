<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use DateInterval;
use DateTimeImmutable;
use Beffroi\Oidc\Domain\Client\AssertionMethodInterface;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Port\ClientAssertionReplayGuardInterface;
use function count;
use function in_array;

/**
 * What a client assertion has to say once its signature has been verified (RFC 7523 §3, OIDC Core §9),
 * the same for every method that carries one. "iss" and "sub" both name the client, so an assertion
 * cannot be presented for another one. "aud" names this provider, once and by one of the names this
 * client may name it by, which AcceptedAssertionAudiences answers: one name and not two, because an
 * assertion made for this provider and for somebody else was made for somebody else. "exp" is there and
 * is bounded, so that an assertion is not a bearer token for a year. "jti" is there and is remembered
 * until "exp", so that an assertion authenticates once.
 */
final readonly class ClientAssertionValidator
{
    /**
     * @param AcceptedAssertionAudiences $audiences the names of this provider this client may name
     * @param DateInterval $maximumLifetime how far ahead of the request an "exp" may be
     * @param DateInterval $leeway what is allowed of the clock of the client, both ways
     */
    public function __construct(
        private ClientAssertionReplayGuardInterface $replays,
        private AcceptedAssertionAudiences $audiences,
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
        $clientId = $client->registration->clientId;
        if ($assertion->claim('iss') !== $clientId || $assertion->claim('sub') !== $clientId) {
            throw $this->refuse($method, $clientId, 'the "iss" and the "sub" of a client assertion both name the client (RFC 7523 section 3)');
        }
        $audiences = $assertion->audiences();
        if (count($audiences) !== 1 || ! in_array($audiences[0], $this->audiences->of($request->tenant, $client), true)) {
            throw $this->refuse(
                $method,
                $clientId,
                'the "aud" of a client assertion names this provider, once, by a name this client may name it by (RFC 7523 section 3, FAPI 2.0 Security Profile section 5.3.2.1, CIBA Core section 7.1)',
            );
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
            throw $this->refuse($method, $client->registration->clientId, 'a client assertion carries a "jti"');
        }
        if (! $this->replays->remember($client, $jti, $expiresAt)) {
            throw ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::ReplayedAssertion, $client->registration->clientId, $method->name());
        }
    }

    private function refuse(AssertionMethodInterface $method, string $clientId, string $reason): ClientAuthenticationFailure
    {
        return ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::InvalidAssertion, $clientId, $method->name(), $reason);
    }
}

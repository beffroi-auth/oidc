<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client;

use function array_filter;
use function array_map;
use function array_values;
use function count;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Client\Method\AuthenticationMethodInterface;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailed;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Heidi\Oidc\Exception\InvalidClientException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use function implode;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use function sprintf;

/**
 * Authenticates the client of a request at every endpoint that authenticates one (RFC 6749 §2.3, §3.2.1,
 * RFC 7662 §2.1, RFC 7009 §2.1). It knows no method: the wired methods say which of them the request
 * presents, the client says which one it registered, and the authenticator is what picks the one and
 * refuses the other. A refusal costs what an acceptance costs, the method paying it against the decoy of
 * the core (issue #124), and reads the same whatever the cause, so that the answer and the time taken
 * say nothing about who is registered (decision 0006).
 */
final readonly class ClientAuthenticator
{
    /**
     * @param ClientAuthenticationMethods $methods the wired methods, which is what a registration reads
     *                                             and what the discovery document announces (issue #98)
     */
    public function __construct(
        private ClientRepositoryInterface $clients,
        private ClientAuthenticationMethods $methods,
        private ClockInterface $clock,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * @param string $endpoint the absolute URL of the endpoint that received the request, which an
     *                         assertion may name as its audience (RFC 7523 §3)
     * @param array<string, mixed> $parameters the form parameters of the request body
     *
     * @throws OAuth2Exception
     */
    public function authenticate(Tenant $tenant, string $endpoint, ?string $authorizationHeader, array $parameters, RequestContext $context): Client
    {
        try {
            $request = new ClientAuthenticationRequest($tenant, $endpoint, $authorizationHeader, $parameters, $context);
            [$method, $clientId] = $this->presentedIn($request);
            $named = $request->clientId();
            if ($named !== null && $named !== $clientId) {
                throw ClientAuthenticationFailure::malformedRequest(ClientAuthenticationFailureReason::MismatchedClientId, $clientId, $method->name(), 'The client_id parameter does not match the credentials presented.');
            }
            $client = $this->clients->findByClientId($tenant, $clientId);
            if ($client === null) {
                $method->payRefusal($request);

                throw ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::UnknownClient, $clientId, $method->name());
            }
            if ($client->authenticationMethod->name() !== $method->name()) {
                $method->payRefusal($request);

                throw ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::UnexpectedMethod, $clientId, $method->name());
            }
            $method->verify($request, $client);

            return $client;
        } catch (ClientAuthenticationFailure $failure) {
            throw $this->announce($tenant, $context, $authorizationHeader, $failure);
        }
    }

    /**
     * Which method the request presents. Two methods that authenticate the client are two mechanisms,
     * which RFC 6749 §2.3 refuses before anything is verified. An Authorization header no method could
     * read is refused whatever the body carries beside it, so that a header the provider does not
     * understand is never silently dropped. A method that authenticates nothing comes last: a public
     * client names itself and carries no credential.
     *
     * @throws ClientAuthenticationFailure
     * @return array{AuthenticationMethodInterface, string}
     */
    private function presentedIn(ClientAuthenticationRequest $request): array
    {
        $presented = [];
        foreach ($this->methods->clientAuthenticationMethods() as $method) {
            $clientId = $method->presentedBy($request);
            if ($clientId !== null) {
                $presented[] = [$method, $clientId];
            }
        }
        $proving = array_values(array_filter($presented, static fn (array $claim): bool => $claim[0]->authenticatesClient()));
        if (count($proving) > 1) {
            throw ClientAuthenticationFailure::malformedRequest(ClientAuthenticationFailureReason::MultipleMechanisms, $proving[0][1], null, sprintf('The client must not use more than one authentication method in a request (RFC 6749 section 2.3); this one uses %s.', implode(' and ', array_map(static fn (array $claim): string => $claim[0]->name(), $proving))));
        }
        if ($proving !== []) {
            return $proving[0];
        }
        if ($request->authorizationHeader !== null) {
            throw ClientAuthenticationFailure::unauthenticated(ClientAuthenticationFailureReason::UnsupportedScheme, 'The Authorization header carries no authentication scheme this provider takes.');
        }
        if ($presented !== []) {
            return $presented[0];
        }

        throw ClientAuthenticationFailure::unauthenticated(ClientAuthenticationFailureReason::NoCredentials, 'The request carries no client authentication.');
    }

    /**
     * The audit trail gets the reason, the client reads the error of RFC 6749 §5.2. The challenge is
     * offered to a client that tried the Authorization header and to no other (RFC 7235 §4.1).
     */
    private function announce(Tenant $tenant, RequestContext $context, ?string $authorizationHeader, ClientAuthenticationFailure $failure): OAuth2Exception
    {
        $this->events->dispatch(new ClientAuthenticationFailed($this->clock->now(), $tenant, $context, $failure->reason, $failure->clientId, $failure->method));
        if ($failure->malformedRequest) {
            return new InvalidRequestException($failure->description);
        }

        return new InvalidClientException($failure->description, $authorizationHeader === null ? null : sprintf('Basic realm="%s"', $tenant->issuer));
    }
}

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client;

use function array_filter;
use function array_find;
use function array_map;
use function array_unique;
use function array_values;
use function count;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Client\Method\AuthenticationMethodInterface;
use Heidi\Oidc\Application\Client\Method\ConfirmingMethodInterface;
use Heidi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Heidi\Oidc\Domain\Client\CertificateBindingMethodInterface;
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
 *
 * What comes back is the client and what it proved beyond being itself: a method that proves a key binds
 * the tokens of the request to it (RFC 8705 §3), and the authenticator carries that without knowing what
 * it is made of.
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
    public function authenticate(
        Tenant $tenant,
        string $endpoint,
        ?string $authorizationHeader,
        array $parameters,
        RequestContext $context,
        ?ClientCertificate $certificate = null,
    ): AuthenticatedClient {
        try {
            $request = new ClientAuthenticationRequest($tenant, $endpoint, $authorizationHeader, $parameters, $context, $certificate);
            [$candidates, $clientId] = $this->presentedIn($request);
            $method = $candidates[0];
            $named = $request->clientId();
            if ($named !== null && $named !== $clientId) {
                throw ClientAuthenticationFailure::malformedRequest(
                    ClientAuthenticationFailureReason::MismatchedClientId,
                    $clientId,
                    $method->name(),
                    'The client_id parameter does not match the credentials presented.',
                );
            }
            $client = $this->clients->findByClientId($tenant, $clientId);
            if ($client === null) {
                $method->payRefusal($request);

                throw ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::UnknownClient, $clientId, $method->name());
            }
            $registered = array_find(
                $candidates,
                static fn (AuthenticationMethodInterface $candidate): bool => $candidate->name() === $client->authenticationMethod->name(),
            );
            if ($registered === null) {
                $method->payRefusal($request);

                throw ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::UnexpectedMethod, $clientId, $method->name());
            }
            $registered->verify($request, $client);

            return new AuthenticatedClient($client, $registered instanceof ConfirmingMethodInterface ? $registered->confirmationOf($request) : null);
        } catch (ClientAuthenticationFailure $failure) {
            throw $this->announce($tenant, $context, $authorizationHeader, $failure);
        }
    }

    /**
     * Which methods the request presents, and which client they name. Credentials of two kinds in one
     * request are two mechanisms, which RFC 6749 §2.3 refuses before anything is verified; two methods
     * reading the one credential the request carries are not, and both come back, the client's
     * registration saying which of them verifies it (RFC 8705 §2, where a certificate is read by either
     * mutual-TLS method and the registration is the only thing that tells them apart).
     *
     * What the connection proves is not a credential the request chose. A client reaching a host whose
     * listener asks for a certificate presents one because it was asked, so a certificate beside a
     * credential of the request is not a second authentication method: the credential of the request
     * authenticates, and the certificate authenticates only the clients registered for a mutual-TLS
     * method. RFC 8705 §3 lets a provider bind the tokens of a client authenticated otherwise to the
     * certificate it presented all the same; that is a registration of its own, which no client has
     * here, and binding a client that never asked for it would break the resource server it calls.
     *
     * An Authorization header no method could read is refused whatever the body carries beside it, so
     * that a header the provider does not understand is never silently dropped. A method that
     * authenticates nothing comes last: a public client names itself and carries no credential.
     *
     * @throws ClientAuthenticationFailure
     * @return array{non-empty-list<AuthenticationMethodInterface>, string}
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
        $chosen = array_values(array_filter($proving, static fn (array $claim): bool => ! $claim[0] instanceof CertificateBindingMethodInterface));
        $proving = $chosen === [] ? $proving : $chosen;
        if ($proving !== []) {
            $mechanisms = array_unique(array_map(static fn (array $claim): string => $claim[0]->mechanism(), $proving));
            if (count($mechanisms) > 1) {
                throw ClientAuthenticationFailure::malformedRequest(
                    ClientAuthenticationFailureReason::MultipleMechanisms,
                    $proving[0][1],
                    null,
                    sprintf('The client must not use more than one authentication method in a request (RFC 6749 section 2.3); this one uses %s.', implode(' and ', array_map(
                        static fn (array $claim): string => $claim[0]->name(),
                        $proving,
                    ))),
                );
            }

            return [array_map(static fn (array $claim): AuthenticationMethodInterface => $claim[0], $proving), $proving[0][1]];
        }
        if ($request->authorizationHeader !== null) {
            throw ClientAuthenticationFailure::unauthenticated(
                ClientAuthenticationFailureReason::UnsupportedScheme,
                'The Authorization header carries no authentication scheme this provider takes.',
            );
        }
        if ($presented !== []) {
            return [[$presented[0][0]], $presented[0][1]];
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

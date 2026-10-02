<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use function array_filter;
use function array_map;
use function array_unique;
use function array_values;
use function count;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\LoadBudgetSpentException;
use Beffroi\Oidc\Application\Client\Method\AuthenticationMethodInterface;
use Beffroi\Oidc\Application\Client\Method\ConfirmingMethodInterface;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailed;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Beffroi\Oidc\Domain\Token\CertificateConfirmation;
use Beffroi\Oidc\Domain\Token\ConfirmationInterface;
use Beffroi\Oidc\Exception\InvalidClientException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Port\ClientLoadBudgetInterface;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
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
 *
 * A client that authenticated takes one of its load budget (decision 0014), here and nowhere else,
 * because this is the one place where its identifier is proven rather than claimed. A method that only
 * names its client takes nothing: a public client is bounded by the budget of its origin, and counting
 * it here would let anyone empty the budget of a client by naming it.
 */
final readonly class ClientAuthenticator
{
    /**
     * @param ClientAuthenticationMethods $methods the wired methods, which is what a registration reads
     *                                              and what the discovery document announces (issue #98)
     * @param ClientAuthenticationRequestParser $requests what reads a request into what the methods read,
     *                                                   the assertion of RFC 7523 §2.2 included, once
     */
    public function __construct(
        private ClientRepositoryInterface $clients,
        private ClientAuthenticationMethods $methods,
        private ClientAuthenticationRequestParser $requests,
        private ClockInterface $clock,
        private EventDispatcherInterface $events,
        private ClientLoadBudgetInterface $budget,
    ) {
    }

    /**
     * @param string $endpoint the absolute URL of the endpoint that received the request, which an
     *                         assertion may name as its audience (RFC 7523 §3)
     * @param array<string, mixed> $parameters the form parameters of the request body
     *
     * @throws OAuth2Exception
     * @throws LoadBudgetSpentException when the client authenticated and its load budget is spent
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
            $request = $this->requests->read($tenant, $endpoint, $authorizationHeader, $parameters, $context, $certificate);
            $presented = $this->presentedIn($request);
            $clientId = $presented->clientId();
            $method = $presented->first();
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
            $registered = $presented->registeredBy($client);
            if ($registered === null) {
                $method->payRefusal($request);

                throw ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::UnexpectedMethod, $clientId, $method->name());
            }
            $registered->verify($request, $client);
            if ($registered->authenticatesClient()) {
                $this->budget->consume($tenant, $clientId);
            }

            return new AuthenticatedClient($client, self::proven($registered, $request, $client));
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
     * method. What that certificate binds is another question, answered by the registration of the
     * client and not here (proven()).
     *
     * An Authorization header no method could read is refused whatever the body carries beside it, so
     * that a header the provider does not understand is never silently dropped. A method that
     * authenticates nothing comes last: a public client names itself and carries no credential.
     *
     * @throws ClientAuthenticationFailure
     */
    private function presentedIn(ClientAuthenticationRequest $request): PresentedCredentials
    {
        $presented = [];
        foreach ($this->methods->clientAuthenticationMethods() as $method) {
            $clientId = $method->presentedBy($request);
            if ($clientId !== null) {
                $presented[] = new PresentedMethod($method, $clientId);
            }
        }
        $proving = array_values(array_filter($presented, static fn (PresentedMethod $claim): bool => $claim->authenticatesClient()));
        $chosen = array_values(array_filter($proving, static fn (PresentedMethod $claim): bool => ! $claim->bindsACertificate()));
        $proving = $chosen === [] ? $proving : $chosen;
        if ($proving !== []) {
            $mechanisms = array_unique(array_map(static fn (PresentedMethod $claim): string => $claim->mechanism(), $proving));
            if (count($mechanisms) > 1) {
                throw ClientAuthenticationFailure::malformedRequest(
                    ClientAuthenticationFailureReason::MultipleMechanisms,
                    $proving[0]->clientId,
                    null,
                    sprintf('The client must not use more than one authentication method in a request (RFC 6749 section 2.3); this one uses %s.', implode(' and ', array_map(
                        static fn (PresentedMethod $claim): string => $claim->name(),
                        $proving,
                    ))),
                );
            }

            return new PresentedCredentials($proving);
        }
        if ($request->authorizationHeader !== null) {
            throw ClientAuthenticationFailure::unauthenticated(
                ClientAuthenticationFailureReason::UnsupportedScheme,
                'The Authorization header carries no authentication scheme this provider takes.',
            );
        }
        if ($presented !== []) {
            return new PresentedCredentials([$presented[0]]);
        }

        throw ClientAuthenticationFailure::unauthenticated(ClientAuthenticationFailureReason::NoCredentials, 'The request carries no client authentication.');
    }

    /**
     * What the request proved beyond being this client, said in the terms a token is bound in (RFC 8705
     * §3, RFC 7800 §3.1). A method that proves the client holds a key says so itself, and what the
     * binding is made of is the method's to say.
     *
     * A client that registered certificate-bound access tokens is bound to the certificate of its
     * connection whichever way it authenticated (RFC 8705 §3.4): the provider may do it for any client
     * and does it for the ones that asked, an assertion proving who the client is and a certificate
     * proving who holds the token that leaves. A client that registered none is not bound to a
     * certificate it presented only because the listener asked for one: binding a client that never
     * asked for it would break the resource server it calls.
     */
    private static function proven(AuthenticationMethodInterface $method, ClientAuthenticationRequest $request, Client $client): ?ConfirmationInterface
    {
        if ($method instanceof ConfirmingMethodInterface) {
            return $method->confirmationOf($request);
        }
        $certificate = $request->certificate;

        return $certificate !== null && $client->registration->requiresCertificateBoundTokens
            ? CertificateConfirmation::ofCertificate($certificate)
            : null;
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

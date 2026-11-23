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
 * RFC 6749 §2.3, §3.2.1, RFC 7662 §2.1, RFC 7009 §2.1
 *
 * Only a proven client spends its load budget: counting a merely named one would let anyone exhaust it.
 */
final readonly class ClientAuthenticator
{
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
     * @param string $endpoint absolute URL
     * @param array<string, mixed> $parameters
     *
     * @throws OAuth2Exception
     * @throws LoadBudgetSpentException
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
     * RFC 6749 §2.3, RFC 8705 §2
     *
     * A certificate the listener asked for is no second mechanism beside a credential of the request.
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
     * RFC 8705 §3, §3.4, RFC 7800 §3.1
     *
     * A certificate presented because the listener asked binds only a client registered for certificate-bound
     * tokens: binding another would break the resource server it calls.
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
     * RFC 6749 §5.2, RFC 7235 §4.1
     */
    private function announce(Tenant $tenant, RequestContext $context, ?string $authorizationHeader, ClientAuthenticationFailure $failure): OAuth2Exception
    {
        $held = $failure->clientId === null ? null : $this->clients->findByClientId($tenant, $failure->clientId);
        $this->events->dispatch(new ClientAuthenticationFailed(
            $this->clock->now(),
            $tenant,
            $context,
            $failure->reason,
            $held?->registration->clientId,
            $failure->method,
        ));
        if ($failure->malformedRequest) {
            return new InvalidRequestException($failure->description);
        }

        return new InvalidClientException($failure->description, $authorizationHeader === null ? null : sprintf('Basic realm="%s"', $tenant->issuer));
    }
}

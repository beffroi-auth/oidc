<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\PushedAuthorization;

use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Request\RequestParameters;
use Heidi\Oidc\Domain\Event\PushedRequestRefusalReason;
use Heidi\Oidc\Domain\Event\PushedRequestRefused;
use Heidi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRequest;
use Heidi\Oidc\Domain\PushedAuthorization\RequestUri;
use Heidi\Oidc\Exception\InvalidRequestUriException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Port\PushedAuthorizationRequestRepositoryInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * What the authorization endpoint reads when the request was pushed (RFC 9126 §4): the "request_uri"
 * names a record, the record carries the parameters, and the query carries nothing else that counts.
 * "client_id" and "request_uri" are the two parameters such a request has; every other one of the query
 * is dropped, as it is for a request object (OIDC Core §6.1), so that what the client pushed and what
 * the provider reads are the same request.
 *
 * A reference is spent once and read by the client it was issued to, and it is spent when the request
 * it carries is granted and not when it is read (FAPI 2.0 Security Profile §5.3.1): a user who reloads
 * the page they were sent to, or a browser that repeats the request, is still holding a request nobody
 * has answered yet. The authorization endpoint consumes the record with the code it issues.
 *
 * What is not a reference of this provider is left alone: the authorization endpoint answers for it, and
 * nothing here ever fetches a URL.
 */
final readonly class PushedAuthorizationRequestResolver
{
    private const string REFUSED = 'The request_uri parameter names no request this provider is holding for this client (RFC 9126 section 4).';

    public function __construct(
        private PushedAuthorizationRequestRepositoryInterface $requests,
        private ClockInterface $clock,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * @param array<string, mixed> $parameters the parameters of the authorization request as the browser carried them
     *
     * @throws OAuth2Exception never redirectable: a pushed request that grants nothing names no redirect
     *                         URI this provider would send anything to
     * @return PushedAuthorizationRequest|null the record the endpoint reads in place of the query, null
     *                                         when the request was not pushed and the query stands
     */
    public function resolve(Tenant $tenant, array $parameters, RequestContext $context): ?PushedAuthorizationRequest
    {
        $requestUri = RequestParameters::single($parameters, 'request_uri', false);
        if ($requestUri === null || ! RequestUri::isOurs($requestUri)) {
            return null;
        }
        $clientId = RequestParameters::single($parameters, 'client_id', false);
        $request = $this->requests->findByRequestUriHash(RequestUri::hashOf($requestUri));
        if ($request === null) {
            throw $this->refuse($tenant, $context, PushedRequestRefusalReason::Unknown, $clientId, null);
        }
        if (! $request->tenant->equals($tenant) || $request->clientId !== $clientId) {
            throw $this->refuse($tenant, $context, PushedRequestRefusalReason::OtherClient, $clientId, $request->clientId);
        }
        if ($request->isExpired($this->clock->now())) {
            throw $this->refuse($tenant, $context, PushedRequestRefusalReason::Expired, $clientId, $request->clientId);
        }
        if ($request->isUsed()) {
            throw $this->refuse($tenant, $context, PushedRequestRefusalReason::AlreadyUsed, $clientId, $request->clientId);
        }

        return $request;
    }

    /**
     * RFC 9126 §4: the parameters of the record, plus the "client_id" the request must carry, which is
     * the one the record is bound to.
     *
     * @return array<string, string|list<string>>
     */
    public static function parametersOf(PushedAuthorizationRequest $request): array
    {
        return [
            ...$request->parameters,
            'client_id' => $request->clientId,
        ];
    }

    /**
     * The audit trail gets the reason and the two clients; the one that presented the reference reads
     * one error whichever of the four it ran into.
     */
    private function refuse(
        Tenant $tenant,
        RequestContext $context,
        PushedRequestRefusalReason $reason,
        ?string $presentedBy,
        ?string $pushedBy,
    ): OAuth2Exception {
        $this->events->dispatch(new PushedRequestRefused($this->clock->now(), $tenant, $reason, $presentedBy, $pushedBy, $context));

        return new InvalidRequestUriException(self::REFUSED);
    }
}

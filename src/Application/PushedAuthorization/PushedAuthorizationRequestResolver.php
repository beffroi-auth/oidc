<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\PushedAuthorization;

use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\Event\PushedRequestRefusalReason;
use Beffroi\Oidc\Domain\Event\PushedRequestRefused;
use Beffroi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRecord;
use Beffroi\Oidc\Domain\PushedAuthorization\RequestUri;
use Beffroi\Oidc\Exception\InvalidRequestUriException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Port\PushedAuthorizationRecordRepositoryInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * RFC 9126 §4
 *
 * A reference is spent when its request is granted, not when read: a reloaded page still holds an unanswered request.
 */
final readonly class PushedAuthorizationRequestResolver
{
    private const string REFUSED = 'The request_uri parameter names no request this provider is holding for this client (RFC 9126 section 4).';

    public function __construct(
        private PushedAuthorizationRecordRepositoryInterface $records,
        private ClockInterface $clock,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * @param array<string, mixed> $parameters
     *
     * @throws OAuth2Exception never redirectable
     */
    public function resolve(Tenant $tenant, array $parameters, RequestContext $context): ?PushedAuthorizationRecord
    {
        $query = RequestParameters::of($parameters);
        $requestUri = $query->optional('request_uri');
        if ($requestUri === null || ! RequestUri::isOurs($requestUri)) {
            return null;
        }
        $clientId = $query->optional('client_id');
        $record = $this->records->findByRequestUriHash(RequestUri::hashOf($requestUri));
        if ($record === null) {
            throw $this->refuse($tenant, $context, PushedRequestRefusalReason::Unknown, $clientId, null);
        }
        if (! $record->tenant->equals($tenant) || $record->clientId !== $clientId) {
            throw $this->refuse($tenant, $context, PushedRequestRefusalReason::OtherClient, $clientId, $record->clientId);
        }
        if ($record->isExpired($this->clock->now())) {
            throw $this->refuse($tenant, $context, PushedRequestRefusalReason::Expired, $clientId, $record->clientId);
        }
        if ($record->isUsed()) {
            throw $this->refuse($tenant, $context, PushedRequestRefusalReason::AlreadyUsed, $clientId, $record->clientId);
        }

        return $record;
    }

    /**
     * @return array<string, string|list<string>>
     */
    public static function parametersOf(PushedAuthorizationRecord $record): array
    {
        return [
            ...$record->parameters,
            'client_id' => $record->clientId,
        ];
    }

    /**
     * The audit trail gets the reason; the client reads one error whatever it ran into.
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

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

use DateTimeImmutable;
use Heidi\Core\Domain\Event\DomainEventInterface;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;

/**
 * A client failed to authenticate at the token endpoint, whatever the reason.
 */
final readonly class ClientAuthenticationFailed implements DomainEventInterface
{
    /**
     * @param string|null $clientId kept as typed
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public RequestContext $context,
        public ClientAuthenticationFailureReason $reason,
        public ?string $clientId,
        public ?TokenEndpointAuthMethod $method,
    ) {
    }
}

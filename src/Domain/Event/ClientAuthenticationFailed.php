<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

use DateTimeImmutable;
use Heidi\Core\Domain\Event\DomainEventInterface;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;

/**
 * A client failed to authenticate at the token endpoint. Announced for every failure, whatever the reason,
 * so that a secret being guessed or a misconfigured relying party shows up in the audit trail.
 */
final readonly class ClientAuthenticationFailed implements DomainEventInterface
{
    /**
     * @param string|null $clientId as the caller presented it, kept as typed; null when none could be read
     * @param TokenEndpointAuthMethod|null $method the method the caller used, when one could be told
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

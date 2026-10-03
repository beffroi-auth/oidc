<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;

/**
 * A client failed to authenticate at the token endpoint, whatever the reason.
 */
final readonly class ClientAuthenticationFailed implements DomainEventInterface
{
    /**
     * The name of the act, which is what the journal writes down (issue #454).
     */
    public const string NAME = 'client_authentication.failed';

    /**
     * @param string|null $clientId kept as typed
     * @param string|null $method the name of the method the request presented, null when the request presented none the provider could name
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public RequestContext $context,
        public ClientAuthenticationFailureReason $reason,
        public ?string $clientId,
        public ?string $method,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;

final readonly class ClientAuthenticationFailed implements DomainEventInterface
{
    public const string NAME = 'client_authentication.failed';

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

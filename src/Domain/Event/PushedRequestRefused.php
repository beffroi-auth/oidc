<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;

/**
 * The "request_uri" itself is never carried: an audit trail must not let its reader replay it.
 */
final readonly class PushedRequestRefused implements DomainEventInterface
{
    public const string NAME = 'pushed_request.refused';

    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public PushedRequestRefusalReason $reason,
        public ?string $presentedBy,
        public ?string $pushedBy,
        public RequestContext $context,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }
}

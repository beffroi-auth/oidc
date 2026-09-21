<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

use DateTimeImmutable;
use Heidi\Core\Domain\Event\DomainEventInterface;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;

/**
 * A "request_uri" was presented at the authorization endpoint and granted nothing (RFC 9126 §4). The
 * reference itself is never carried here: what an audit trail keeps must not let a reader replay it.
 */
final readonly class PushedRequestRefused implements DomainEventInterface
{
    /**
     * @param string|null $presentedBy the "client_id" of the authorization request, null when it carries none
     * @param string|null $pushedBy the client the record is bound to, null when no record was found
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public PushedRequestRefusalReason $reason,
        public ?string $presentedBy,
        public ?string $pushedBy,
        public RequestContext $context,
    ) {
    }
}

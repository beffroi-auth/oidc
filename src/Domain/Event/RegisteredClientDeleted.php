<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

use DateTimeImmutable;
use Heidi\Core\Domain\Event\DomainEventInterface;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;

/**
 * A client this provider had registered itself is gone (RFC 7592 §2.3, decision 0009). One event for one
 * thing happening, whichever way it happened: the client deleted itself at its configuration endpoint, or
 * the timed step dropped it for want of use. Whoever reads this learns that no request of that client
 * will be served again, and not which of the two it was.
 *
 * It names the client by its identifier and carries nothing of the client itself: a client carries the
 * reader of its "jwks_uri", which no broker can be sent.
 */
final readonly class RegisteredClientDeleted implements DomainEventInterface
{
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $clientId,
        public RequestContext $context,
    ) {
    }
}

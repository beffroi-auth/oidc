<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;

/**
 * A client this provider had registered itself is gone (RFC 7592 §2.3, decision 0009). One event for one
 * thing happening, whichever way it happened: the client deleted itself at its configuration endpoint, or
 * the timed step dropped it for want of use. Whoever reads this learns that no request of that client
 * will be served again, and not which of the two it was.
 *
 * It names the client by its identifier and carries nothing of the client itself: a client carries the
 * reader of its "jwks_uri", which no broker can be sent.
 */
final readonly class RegisteredClientDeleted implements ConcernsAClientInterface
{
    /**
     * The name of the act, which is what the journal writes down (issue #454).
     */
    public const string NAME = 'registered_client.deleted';

    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $clientId,
        public RequestContext $context,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }
}

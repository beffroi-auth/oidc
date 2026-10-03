<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use Beffroi\Core\Domain\Event\DomainEventInterface;

/**
 * An event that names a client of this provider, which is what lets the journal say on whose behalf an
 * act was done (issue #454).
 *
 * The identifier it was registered under, and never the client: a client carries the reader of its
 * "jwks_uri", so no broker could be sent one, and a row of the journal names what a reader of that row
 * can look up.
 *
 * That a client is being *used* is a narrower fact of the same shape, which is why ClientInUseInterface
 * extends this one: two events mean it, where many name a client without anybody using it, a refusal and
 * a deletion among them.
 */
interface ConcernsAClientInterface extends DomainEventInterface
{
    /**
     * The client the act concerns, by the identifier it was registered under.
     */
    public string $clientId { get; }
}

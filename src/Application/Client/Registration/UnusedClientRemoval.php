<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Registration;

use function count;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Port\ClientRegistrationPolicyInterface;
use Heidi\Oidc\Port\UnusedClientsInterface;
use Psr\Clock\ClockInterface;

/**
 * The hygiene decision 0009 makes part of itself: a client nobody uses any more is deleted, after a duration
 * its tenant names. Clients that are never cleaned up are a table that only grows and, worse, `redirect_uris`
 * nobody watches any more: a domain expires, a subdomain is released, and a URI this provider still sends
 * browsers with authorization codes to belongs to somebody else.
 *
 * It asks **each source of clients what it may drop**, and a source that holds declarations is asked
 * nothing, having none of that to answer: that is how "a client a deployment declared is never deleted" is a
 * property of the wiring rather than a condition here. What it does with what it is given is what the client
 * configuration endpoint does with a `DELETE` (`RegisteredClientRemoval`), so one event says a client is
 * gone whichever way it went.
 *
 * **A run is bounded.** A step that locks a table on a large deployment is an outage, so it removes at most
 * what it is given and leaves the rest to the next run; it is recurring and idempotent, so a backlog is
 * caught up rather than lost, and the clients that have waited longest go first.
 *
 * A tenant with no registration policy has no client that registered itself, so there is nothing to keep and
 * nothing to drop: a deployment that registers nobody never reads a row for this.
 */
final readonly class UnusedClientRemoval
{
    /**
     * How many clients one run removes at most.
     */
    public const int PER_RUN = 100;

    /**
     * @param iterable<UnusedClientsInterface> $sources the sources that hold rows, in the order they are wired
     */
    public function __construct(
        private iterable $sources,
        private ClientRegistrationPolicyInterface $policies,
        private RegisteredClientRemoval $removal,
        private ClockInterface $clock,
        private int $perRun = self::PER_RUN,
    ) {
    }

    /**
     * @return list<string> the clients removed, by their identifiers, in the order they were removed
     */
    public function removeUnused(Tenant $tenant, RequestContext $context): array
    {
        $policy = $this->policies->policyFor($tenant);
        if ($policy === null) {
            return [];
        }
        $retention = $policy->retentionAt($this->clock->now());
        $removed = [];
        foreach ($this->sources as $source) {
            $left = $this->perRun - count($removed);
            if ($left <= 0) {
                break;
            }
            foreach ($source->unusedIn($tenant, $retention, $left) as $record) {
                $this->removal->remove($record, $context);
                $removed[] = $record->clientId;
            }
        }

        return $removed;
    }
}

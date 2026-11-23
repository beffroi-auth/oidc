<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use function count;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\ClientRetentionPolicyInterface;
use Beffroi\Oidc\Port\UnusedClientsInterface;
use Psr\Clock\ClockInterface;

final readonly class UnusedClientRemoval
{
    /**
     * Bounded so that a run never locks the table long enough to be an outage.
     */
    public const int PER_RUN = 100;

    /**
     * @param iterable<UnusedClientsInterface> $sources
     */
    public function __construct(
        private iterable $sources,
        private ClientRetentionPolicyInterface $retentions,
        private RegisteredClientRemoval $removal,
        private ClockInterface $clock,
        private int $perRun = self::PER_RUN,
    ) {
    }

    /**
     * @return list<string> the identifiers of the clients removed
     */
    public function removeUnused(Tenant $tenant, RequestContext $context): array
    {
        $retention = $this->retentions->retentionFor($tenant, $this->clock->now());
        if ($retention === null) {
            return [];
        }
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

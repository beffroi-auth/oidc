<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Registration\ClientRetention;

/**
 * Decision 0009: in every mode, closed included, a client registered once is deleted after a time unused.
 */
interface ClientRetentionPolicyInterface
{
    /**
     * @return ClientRetention|null null for a tenant this deployment does not serve
     */
    public function retentionFor(Tenant $tenant, DateTimeImmutable $now): ?ClientRetention;
}

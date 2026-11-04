<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Disclosure\Disclosure;
use DateTimeImmutable;

interface DisclosuresInterface
{
    public function record(Disclosure $disclosure): void;

    /**
     * Forgets a bounded number of rows and says how many: a backlog is worked through over several runs.
     */
    public function forgetBefore(Tenant $tenant, DateTimeImmutable $moment): int;
}

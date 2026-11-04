<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Disclosure;

use Beffroi\Core\Domain\Listing\RetentionWindow;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Port\DisclosuresInterface;
use Psr\Clock\ClockInterface;

final readonly class DisclosureRetention
{
    public function __construct(
        private DisclosuresInterface $disclosures,
        private ClockInterface $clock,
        private RetentionWindow $window,
    ) {
    }

    public function enforce(Tenant $tenant): int
    {
        return $this->disclosures->forgetBefore($tenant, $this->window->keptSince($this->clock->now()));
    }
}

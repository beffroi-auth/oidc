<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Disclosure;

use Beffroi\Core\Domain\Listing\RetentionWindow;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;

final readonly class DisclosureRetention
{
    public function __construct(
        private ClockInterface $clock,
        public RetentionWindow $window,
    ) {
    }

    public function keptSince(): DateTimeImmutable
    {
        return $this->window->keptSince($this->clock->now());
    }
}

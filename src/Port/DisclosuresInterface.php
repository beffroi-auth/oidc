<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Disclosure\Disclosure;

interface DisclosuresInterface
{
    /**
     * What was given takes the next position of the chain of the disclosures of its tenant.
     */
    public function record(Disclosure $disclosure): void;
}

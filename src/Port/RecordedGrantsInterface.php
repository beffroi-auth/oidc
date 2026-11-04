<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Grant\GrantRecord;
use Symfony\Component\Uid\Uuid;

interface RecordedGrantsInterface
{
    public function findByGrantId(Uuid $grantId): ?GrantRecord;
}

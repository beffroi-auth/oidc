<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Ciba\PendingApproval;

/**
 * What it is handed carries no identifier of the request and no link that answers one: a message reaching a user
 * this way is exactly what an attacker would like to write.
 */
interface PendingApprovalNotifierInterface
{
    public function tell(PendingApproval $approval): void;
}

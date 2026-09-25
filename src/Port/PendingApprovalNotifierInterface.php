<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Ciba\PendingApproval;

/**
 * A way of reaching a user (architecture §5.6): what the provider calls when somebody has to be told that
 * a request is waiting for them, in a flow where nobody is in front of a browser of ours (CIBA Core §7).
 *
 * It names a way of reaching somebody and never a channel: a deployment that sends a push notification
 * and one that sends a mail implement this same interface, and neither is named here. What it is handed
 * carries no identifier of the request and no link that answers one, because what reaches a user this way
 * is exactly what an attacker would like to write (BCP 10027 §5.2).
 *
 * Reaching somebody is not part of answering the client: an implementation that talks to a third party
 * hands the work on rather than doing it in the request (the bundle's own puts it on the notifications
 * lane), and a user who is not reached still finds the request on the page where requests are answered.
 */
interface PendingApprovalNotifierInterface
{
    public function tell(PendingApproval $approval): void;
}

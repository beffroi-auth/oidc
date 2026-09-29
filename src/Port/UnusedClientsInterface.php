<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\ClientRecord;
use Heidi\Oidc\Domain\Client\Registration\ClientRetention;

/**
 * What a source of clients may drop (decision 0009). A source that holds declarations implements none of
 * this and is wired for none of it, which is how "a client a deployment declared is never deleted" is a
 * property of the wiring rather than a condition in the step that deletes: there is nothing to ask it.
 *
 * It answers what may go and never removes it: one thing removes a client, whichever way the client went
 * (`RegisteredClientRemoval`), so that the delete of RFC 7592 §2.3 and the timed step do the same thing and
 * emit the same event.
 */
interface UnusedClientsInterface
{
    /**
     * @param int $limit how many this call may answer, at most; a run of the step is bounded so that it
     *                   cannot lock a table on a large deployment, and what it leaves the next run catches
     *
     * @return list<ClientRecord> the clients of that tenant this source may drop, oldest use first so that
     *                            a bounded run takes the ones that have waited longest
     */
    public function unusedIn(Tenant $tenant, ClientRetention $retention, int $limit): array;
}

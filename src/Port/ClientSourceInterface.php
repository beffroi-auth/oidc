<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\ClientRegistration;

/**
 * Where the clients of a tenant come from (architecture §4.1). A deployment has one at least, the clients
 * it declared, and as many as it wires: the clients that registered themselves are another, and a third
 * is a class that implements this and a line in the wiring, never a case added to something that knows
 * how many there are.
 *
 * A source answers two things and no more: which client of a tenant carries an identifier, and what it
 * holds for that tenant. Everything a question about the **set** of clients needs is derived from the
 * second, once and in one place (`RegisteredClients`), so that a source added later brings no rule with
 * it and no rule is written a second time in the idiom of its store.
 */
interface ClientSourceInterface extends ClientRepositoryInterface
{
    /**
     * @return iterable<ClientRegistration> what this source holds for that tenant, in the order it holds
     *                                      them; nothing for a tenant it holds no client of
     */
    public function registrationsIn(Tenant $tenant): iterable;
}

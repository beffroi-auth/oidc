<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Administration\ActingAdministrator;
use Beffroi\Oidc\Exception\PersonsBudgetSpentException;

/**
 * How many persons the reads of one administrator deliver in a window (decision 0014), counted by tenant and by the
 * person the token of the request was issued for: never by a client or an address, which several administrators may
 * share.
 */
interface PersonsBudgetInterface
{
    /**
     * @param int $persons one or more, spent whole or not at all
     *
     * @throws PersonsBudgetSpentException
     */
    public function spend(ActingAdministrator $administrator, int $persons): void;
}

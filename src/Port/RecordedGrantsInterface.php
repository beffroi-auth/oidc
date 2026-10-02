<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Grant\GrantRecord;
use Symfony\Component\Uid\Uuid;

/**
 * Where the grant a token says it descends from is found (architecture §4.6). The question is one, and it
 * is asked of the record that carries the grant whichever flow wrote it: an authorization code, a device
 * authorization request, a backchannel authentication request. A store answers for the records it keeps
 * and says nothing of the others, so a flow that draws a record of its own is a store wired here and never
 * a branch added to the reader.
 */
interface RecordedGrantsInterface
{
    /**
     * @return GrantRecord|null null when this store keeps no record of that grant, which of any one store
     *                          is the ordinary answer
     */
    public function findByGrantId(Uuid $grantId): ?GrantRecord;
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Oidc\Domain\Event\ClientInUseInterface;
use Beffroi\Oidc\Port\ClientStoreInterface;

/**
 * The date a stored client carries of its last use (decision 0009), written from the events that say
 * somebody is using it (`ClientInUseInterface`). It is a date and not a counter: what the removal asks is
 * "when", and a counter would be a second thing to keep right.
 *
 * It is done on the event and therefore after the request that raised it, because nothing of the protocol
 * waits for this: a client is served whether or not the date has been written yet, and a write that was
 * lost costs the client its next quarter of an hour of grace and nothing else.
 *
 * A client a deployment declared has no row, so there is nothing to write and nothing is written: the store
 * answers no record for it, and a declared client is never deleted for want of use.
 */
final readonly class ClientUseRecording
{
    public function __construct(
        private ClientStoreInterface $clients,
    ) {
    }

    public function record(ClientInUseInterface $event): void
    {
        $record = $this->clients->findRecord($event->tenant, $event->clientId);
        if ($record === null) {
            return;
        }
        $record->recordUse($event->occurredAt);
        $this->clients->save($record);
    }
}

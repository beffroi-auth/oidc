<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Oidc\Domain\Event\ClientInUseInterface;
use Beffroi\Oidc\Port\ClientStoreInterface;

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

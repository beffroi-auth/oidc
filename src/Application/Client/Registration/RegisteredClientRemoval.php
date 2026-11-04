<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Event\RegisteredClientDeleted;
use Beffroi\Oidc\Port\ClientStoreInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * RFC 7592 §2.3
 *
 * Records naming the client stay: they resolve through the sources, so nothing of a removed client can be spent.
 */
final readonly class RegisteredClientRemoval
{
    public function __construct(
        private ClientStoreInterface $clients,
        private EventDispatcherInterface $events,
    ) {
    }

    public function remove(ClientRecord $record, RequestContext $context): void
    {
        $this->clients->remove($record);
        $this->events->dispatch(new RegisteredClientDeleted($context->receivedAt, $record->tenant, $record->clientId, $context));
    }
}

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Registration;

use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Oidc\Domain\Client\ClientRecord;
use Heidi\Oidc\Domain\Event\RegisteredClientDeleted;
use Heidi\Oidc\Port\ClientStoreInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * A client this provider registered goes away. **One thing does it, whichever way it went**: the client
 * deleting itself at its configuration endpoint (RFC 7592 §2.3) and the timed step dropping one nobody uses
 * (decision 0009) are the same thing happening, so they remove the row the same way and emit the same
 * event.
 *
 * What names that client elsewhere is left where it is, and that is the answer rather than an omission. A
 * consent, a grant, a refresh token family, an authorization code, a pushed request, a backchannel request
 * and an interaction all keep the identifier of their client and are resolved through the sources at the
 * moment they are read: a record whose client no longer resolves is a record nobody finds, so **nothing of
 * a deleted client can be spent**, which is the "invalidate" RFC 7592 §2.3 asks for. Removing the rows
 * themselves is the general question of rows that can no longer do anything, and it is not this one.
 *
 * A session is not touched at all: a session belongs to the user who opened it, and a client going away is
 * no reason to sign anybody out.
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

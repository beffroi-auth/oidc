<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Registration;

use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Event\RegisteredClientDeleted;
use Heidi\Oidc\Exception\UnauthorizedClientConfigurationException;
use Heidi\Oidc\Port\ClientStoreInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;

/**
 * A client deletes itself (RFC 7592 §2.3): the row is gone, and the token that read it is a token nobody
 * holds a client for, so the same request made again is refused exactly as one of a client nobody
 * registered.
 *
 * It emits the one event a client going away emits, whichever way it went: the timed step that drops a
 * client nobody uses emits the same one, because one thing happened.
 *
 * What becomes of a consent, a grant or a refresh token family that named this client is not read here.
 * Nothing of them can be spent any more, a record whose client no longer resolves being a record nobody
 * finds; what is done with the rows themselves is answered where rows that can no longer do anything are
 * answered for, and this endpoint calls it.
 */
final readonly class ClientConfigurationRemoval
{
    public function __construct(
        private ClientConfigurationAccess $access,
        private ClientStoreInterface $clients,
        private EventDispatcherInterface $events,
    ) {
    }

    /**
     * @throws UnauthorizedClientConfigurationException when the request reads no client of that tenant
     */
    public function remove(
        Tenant $tenant,
        string $clientId,
        #[SensitiveParameter]
        ?string $authorizationHeader,
        RequestContext $context,
    ): void {
        $record = $this->access->granted($tenant, $clientId, $authorizationHeader);
        $this->clients->remove($record);
        $this->events->dispatch(new RegisteredClientDeleted($context->receivedAt, $tenant, $record->clientId, $context));
    }
}

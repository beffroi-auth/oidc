<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Symfony\Component\Uid\Uuid;

/**
 * A logout token was minted for one client of a session that ended (Back-Channel Logout 1.0 §2.6).
 * Carrying it to the URI the client registered is the integration's, asynchronously (architecture §5.6):
 * a client that does not answer never keeps a session open at the provider.
 */
final readonly class LogoutTokenIssued implements DomainEventInterface
{
    /**
     * @param ClientUri $logoutUri the back-channel logout URI of the client, named here so that the sender has nothing to decide
     * @param string $token the compact JWS, the one parameter of the request to come
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $clientId,
        public ClientUri $logoutUri,
        public Uuid $sessionId,
        public string $token,
        public RequestContext $context,
    ) {
    }
}

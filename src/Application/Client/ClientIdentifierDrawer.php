<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Secret\SecretDrawer;
use Heidi\Oidc\Exception\LogicException;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use function sprintf;

/**
 * The identifier a client that registers itself is given (RFC 7591 §3.2.1): the provider assigns it, so
 * it is drawn where every other value this provider hands out and recognises again is drawn, and a
 * request that names one of its own does not get it.
 *
 * A draw any wired source already holds is not served: the identifier of a client is the name the tenant
 * answers to it by, and two clients under one name would be one client with two registrations. Two
 * hundred and fifty-six bits make a collision a thing that does not happen; what makes it impossible is
 * that the draw is looked up before it is served.
 */
final readonly class ClientIdentifierDrawer
{
    /**
     * Past the first draw, the store is answering about something else: a second is drawn rather than a
     * registration refused, and a third says the deployment has a problem no registration can fix.
     */
    private const int DRAWS = 3;

    public function __construct(
        private SecretDrawer $drawer,
        private ClientRepositoryInterface $clients,
    ) {
    }

    /**
     * @throws LogicException when every draw is already held, which is not a thing a client did
     */
    public function drawFor(Tenant $tenant): string
    {
        for ($draw = 0; $draw < self::DRAWS; $draw++) {
            $clientId = $this->drawer->draw();
            if ($this->clients->findByClientId($tenant, $clientId) === null) {
                return $clientId;
            }
        }

        throw new LogicException(sprintf('Three drawn client identifiers were already held by the tenant "%s".', $tenant->slug));
    }
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Secret\SecretDrawer;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use function sprintf;

/**
 * RFC 7591 §3.2.1
 *
 * Every draw is looked up in every source: 256 bits make a collision unlikely, the lookup makes it impossible.
 */
final readonly class ClientIdentifierDrawer
{
    private const int DRAWS = 3;

    public function __construct(
        private SecretDrawer $drawer,
        private ClientRepositoryInterface $clients,
    ) {
    }

    /**
     * @throws LogicException when every draw is already held
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

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Exception\UnauthorizedClientConfigurationException;
use SensitiveParameter;

/**
 * RFC 7592 §2.3
 */
final readonly class ClientConfigurationRemoval
{
    public function __construct(
        private ClientConfigurationAccess $access,
        private RegisteredClientRemoval $removal,
    ) {
    }

    /**
     * @throws UnauthorizedClientConfigurationException
     */
    public function remove(
        Tenant $tenant,
        string $clientId,
        #[SensitiveParameter]
        ?string $authorizationHeader,
        RequestContext $context,
    ): void {
        $this->removal->remove($this->access->granted($tenant, $clientId, $authorizationHeader), $context);
    }
}

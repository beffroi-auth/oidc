<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Exception\UnauthorizedClientConfigurationException;
use SensitiveParameter;

/**
 * A client deletes itself (RFC 7592 §2.3): the row is gone, and the token that read it is a token nobody
 * holds a client for, so the same request made again is refused exactly as one of a client nobody
 * registered.
 *
 * What it does with the client is what the timed step does with one nobody uses any more
 * (`RegisteredClientRemoval`): one thing removes a client and one event says it is gone, because one thing
 * happened whichever way it happened.
 */
final readonly class ClientConfigurationRemoval
{
    public function __construct(
        private ClientConfigurationAccess $access,
        private RegisteredClientRemoval $removal,
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
        $this->removal->remove($this->access->granted($tenant, $clientId, $authorizationHeader), $context);
    }
}

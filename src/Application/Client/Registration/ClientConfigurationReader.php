<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Registration;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Registration\ClientInformationResponse;
use Heidi\Oidc\Exception\UnauthorizedClientConfigurationException;
use Heidi\Oidc\Port\ClientConfigurationEndpointInterface;
use SensitiveParameter;

/**
 * A client reads itself (RFC 7592 §2.1): the registration as the provider holds it, which is what it sent
 * and what the policy of its tenant wrote on it, under the identifier and the date the provider assigned.
 *
 * A command that reads is not the command that writes, so this one writes nothing at all: the registration
 * access token is not rotated on the answer, which §2.3 permits and does not require, and no module asks
 * for. Neither the secret nor the token is answered again; each was said once, and what the row keeps of
 * them recognises them without reading them back.
 */
final readonly class ClientConfigurationReader
{
    public function __construct(
        private ClientConfigurationAccess $access,
        private ClientConfigurationEndpointInterface $endpoints,
    ) {
    }

    /**
     * @throws UnauthorizedClientConfigurationException when the request reads no client of that tenant
     */
    public function read(Tenant $tenant, string $clientId, #[SensitiveParameter] ?string $authorizationHeader): ClientInformationResponse
    {
        $record = $this->access->granted($tenant, $clientId, $authorizationHeader);

        return new ClientInformationResponse(
            ClientInformationResponse::INFORMED,
            $record,
            $this->endpoints->clientConfigurationFor($tenant, $record->clientId),
        );
    }
}

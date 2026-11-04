<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Registration\ClientInformationResponse;
use Beffroi\Oidc\Exception\UnauthorizedClientConfigurationException;
use Beffroi\Oidc\Port\ClientConfigurationEndpointInterface;
use SensitiveParameter;

/**
 * RFC 7592 §2.1
 *
 * Neither the secret nor the token is answered again: what is kept recognises them without reading them back.
 */
final readonly class ClientConfigurationReader
{
    public function __construct(
        private ClientConfigurationAccess $access,
        private ClientConfigurationEndpointInterface $endpoints,
    ) {
    }

    /**
     * @throws UnauthorizedClientConfigurationException
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

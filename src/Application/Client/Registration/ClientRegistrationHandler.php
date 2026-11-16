<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Client\ClientIdentifierDrawer;
use Beffroi\Oidc\Application\Secret\SecretDrawer;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Client\Registration\ClientInformationResponse;
use Beffroi\Oidc\Domain\Client\Registration\RegistrationRequest;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\ClientRegistrationNotOfferedException;
use Beffroi\Oidc\Exception\UnauthorizedRegistrationException;
use Beffroi\Oidc\Exception\UnreadableClientMetadataException;
use Beffroi\Oidc\Port\ClientConfigurationEndpointInterface;
use Beffroi\Oidc\Port\ClientRegistrationPolicyInterface;
use Beffroi\Oidc\Port\ClientStoreInterface;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §3.1
 *
 * What authorises the request is spent before the metadata is read, so a refused registration spends it too.
 */
final readonly class ClientRegistrationHandler
{
    public function __construct(
        private ClientRegistrationPolicyInterface $policies,
        private RegistrationAuthorizations $authorizations,
        private RegistrationUnderThePolicy $registrations,
        private ClientIdentifierDrawer $identifiers,
        private SecretDrawer $secrets,
        private ClientStoreInterface $clients,
        private ClientConfigurationEndpointInterface $endpoints,
        private ClockInterface $clock,
    ) {
    }

    /**
     * @throws ClientRegistrationNotOfferedException
     * @throws UnauthorizedRegistrationException
     * @throws UnreadableClientMetadataException
     */
    public function handle(Tenant $tenant, RegistrationRequest $request): ClientInformationResponse
    {
        $policy = $this->policies->policyFor($tenant);
        if ($policy === null) {
            throw new ClientRegistrationNotOfferedException();
        }
        $authorized = $this->authorizations->authorizing($policy)->authorize($tenant, $request, $policy);
        $clientId = $this->identifiers->drawFor($tenant);
        $kept = $this->registrations->read(
            $tenant,
            $clientId,
            $authorized->inFront,
            $request->members(),
            $policy,
            granted: $authorized->granted,
            administration: $authorized->administration,
        );

        $registrationAccessToken = $this->secrets->draw();
        $record = new ClientRecord(
            Uuid::v7(),
            $tenant,
            $clientId,
            $kept->metadata,
            $kept->assigned,
            $kept->secret,
            DrawnSecret::digestOf($registrationAccessToken),
            $this->clock->now(),
            attested: $kept->attested,
            granted: $authorized->granted?->toDocument(),
            administration: $authorized->administration,
        );
        $this->clients->save($record);

        return new ClientInformationResponse(
            ClientInformationResponse::REGISTERED,
            $record,
            $this->endpoints->clientConfigurationFor($tenant, $clientId),
            $kept->drawnSecret,
            $registrationAccessToken,
        );
    }
}

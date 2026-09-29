<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Registration;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Client\ClientIdentifierDrawer;
use Heidi\Oidc\Application\Secret\SecretDrawer;
use Heidi\Oidc\Domain\Client\ClientRecord;
use Heidi\Oidc\Domain\Client\Registration\ClientInformationResponse;
use Heidi\Oidc\Domain\Client\Registration\RegistrationRequest;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Exception\ClientRegistrationNotOfferedException;
use Heidi\Oidc\Exception\UnauthorizedRegistrationException;
use Heidi\Oidc\Exception\UnreadableClientMetadataException;
use Heidi\Oidc\Port\ClientConfigurationEndpointInterface;
use Heidi\Oidc\Port\ClientRegistrationPolicyInterface;
use Heidi\Oidc\Port\ClientStoreInterface;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The registration endpoint (RFC 7591 §3.1): a client this provider has never seen asks to exist, and
 * leaves with an identifier, the metadata the provider registered, the secret the method it registered
 * needs, and the token and the URI it reads, replaces and deletes itself with (RFC 7592 §3).
 *
 * The order is the order of what each step may refuse. The tenant first, because a tenant that registers
 * nobody has no endpoint at all and nothing of the request is read for it (decision 0009). Then what
 * authorises the request, which is a class per mode and never a mode read here: it is spent before the
 * registration is read, so that a token worth one client registers one whether what followed it was
 * written or refused. Then the registration itself, read under the policy of the tenant by the one thing
 * that reads one (`RegistrationUnderThePolicy`), which is also what a replacement goes through.
 *
 * The two credentials are the things the metadata never carries: RFC 7591 §2 has a member for neither and
 * the provider assigns both (§3.2.1). Each is drawn like every other value this provider hands out,
 * answered once, and kept only as what recognises it again.
 *
 * The write is synchronous and the reason is the protocol's: the client leaves with the identifier the
 * provider drew for it, so the row exists before the answer does (apps/op/config/packages/messenger.yaml).
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
     * @throws ClientRegistrationNotOfferedException when the tenant registers nobody, which is a 404 and
     *                                               not a refusal of anything the request carried
     * @throws UnauthorizedRegistrationException when nothing the request presents authorises a registration
     * @throws UnreadableClientMetadataException when the metadata does not hold together, which is the
     *                                           400 of RFC 7591 §3.2.2 under the error its subclass names
     */
    public function handle(Tenant $tenant, RegistrationRequest $request): ClientInformationResponse
    {
        $policy = $this->policies->policyFor($tenant);
        if ($policy === null) {
            throw new ClientRegistrationNotOfferedException();
        }
        $inFront = $this->authorizations->authorizing($policy)->authorize($tenant, $request);
        $clientId = $this->identifiers->drawFor($tenant);
        $kept = $this->registrations->read($tenant, $clientId, $inFront, $request->members(), $policy);

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

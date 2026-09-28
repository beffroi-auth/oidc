<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Registration;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Oidc\Application\Client\ClientIdentifierDrawer;
use Heidi\Oidc\Application\Client\ClientMetadataReader;
use Heidi\Oidc\Application\Client\Method\SecretKeepingMethodInterface;
use Heidi\Oidc\Application\Secret\SecretDrawer;
use Heidi\Oidc\Domain\Client\ClientRecord;
use Heidi\Oidc\Domain\Client\Metadata\AssignedMembers;
use Heidi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Heidi\Oidc\Domain\Client\Metadata\RegisteredMembers;
use Heidi\Oidc\Domain\Client\Metadata\SpecifiedDefaults;
use Heidi\Oidc\Domain\Client\Registration\ClientRegistrationResponse;
use Heidi\Oidc\Domain\Client\Registration\RegistrationRequest;
use Heidi\Oidc\Exception\ClientRegistrationNotOfferedException;
use Heidi\Oidc\Exception\UnauthorizedRegistrationException;
use Heidi\Oidc\Exception\UnreadableClientMetadataException;
use Heidi\Oidc\Port\ClientRegistrationPolicyInterface;
use Heidi\Oidc\Port\ClientStoreInterface;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The registration endpoint (RFC 7591 §3.1): a client this provider has never seen asks to exist, and
 * leaves with an identifier, the metadata the provider registered and the secret the method it
 * registered needs.
 *
 * The order is the order of what each step may refuse. The tenant first, because a tenant that registers
 * nobody has no endpoint at all and nothing of the request is read for it (decision 0009). Then what
 * authorises the request, which is a class per mode and never a mode read here: it is spent before the
 * registration is read, so that a token worth one client registers one whether what followed it was
 * written or refused. Then the registration itself, read by the one reader every registration goes
 * through, and held to what the tenant offers where the wiring is not already what says so.
 *
 * The secret is the one thing the metadata never carries: RFC 7591 §2 has no member for it and the
 * provider assigns it (§3.2.1), exactly when the registered method proves one. It is drawn like every
 * other value this provider hands out, answered once, and kept only in the shape that method verifies
 * against.
 *
 * The write is synchronous and the reason is the protocol's: the client leaves with the identifier the
 * provider drew for it, so the row exists before the answer does (apps/op/config/packages/messenger.yaml).
 */
final readonly class ClientRegistrationHandler
{
    public function __construct(
        private ClientRegistrationPolicyInterface $policies,
        private RegistrationAuthorizations $authorizations,
        private ClientMetadataReader $reader,
        private ClientIdentifierDrawer $identifiers,
        private RegistrationHeldToTheTenant $tenantOffer,
        private SecretDrawer $secrets,
        private PasswordHasherInterface $hasher,
        private ClientStoreInterface $clients,
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
    public function handle(Tenant $tenant, RegistrationRequest $request): ClientRegistrationResponse
    {
        $policy = $this->policies->policyFor($tenant);
        if ($policy === null) {
            throw new ClientRegistrationNotOfferedException();
        }
        $sent = [
            ...$this->authorizations->authorizing($policy)->authorize($tenant, $request),
            new RegisteredMembers($request->members),
        ];
        $clientId = $this->identifiers->drawFor($tenant);

        // What the policy writes is known only once the method is: it exempts a confidential client from
        // PKCE and never a public one (decision 0017), and the provider assigns a secret exactly when the
        // method proves one (RFC 7591 §3.2.1). One member answers both, and it is read once.
        $method = $this->reader->authenticationMethodOf($clientId, new ClientMetadata([...$sent, new SpecifiedDefaults()]));
        $assigned = new AssignedMembers($policy->membersWrittenOn($method));
        $metadata = new ClientMetadata([...$sent, $assigned, new SpecifiedDefaults()]);
        $secret = $method instanceof SecretKeepingMethodInterface ? $this->secrets->draw() : null;

        $registration = $this->reader->read($clientId, $metadata, $secret !== null);
        $this->tenantOffer->assertHolds($tenant, $registration, $metadata);

        $record = new ClientRecord(
            Uuid::v7(),
            $tenant,
            $clientId,
            $request->members,
            $assigned->members(),
            $secret === null ? null : $method->keep($secret, $this->hasher),
            $this->clock->now(),
        );
        $this->clients->save($record);

        return new ClientRegistrationResponse($record, $secret);
    }
}

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Registration;

use function array_reverse;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Oidc\Application\Client\ClientMetadataReader;
use Heidi\Oidc\Application\Client\Method\SecretKeepingMethodInterface;
use Heidi\Oidc\Application\Secret\SecretDrawer;
use Heidi\Oidc\Domain\Client\ClientSecretInterface;
use Heidi\Oidc\Domain\Client\Metadata\AssignedMembers;
use Heidi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Heidi\Oidc\Domain\Client\Metadata\ClientMetadataSourceInterface;
use Heidi\Oidc\Domain\Client\Metadata\RegisteredMembers;
use Heidi\Oidc\Domain\Client\Metadata\SpecifiedDefaults;
use Heidi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Heidi\Oidc\Exception\UnreadableClientMetadataException;

/**
 * A registration the provider is about to write, read under the policy of its tenant: the creation of
 * RFC 7591 §3.1 and the replacement of RFC 7592 §2.2 go through this and through nothing else, which is
 * what makes **an update unable to reach what a registration could not**.
 *
 * What it does, in the order of what each step may refuse: the members the client sent, behind whatever
 * an authorisation put in front of them (RFC 7591 §3.1.1) and in front of the defaults of §2; the
 * authentication method read on its own, because two answers hang on that one member before the
 * registration exists; the members the policy writes, which it writes on a confidential client and never
 * on a public one (decision 0017); the secret, which the provider assigns exactly when the registered
 * method proves one and which a client that already holds one keeps; then the registration itself, read
 * by the one reader every registration goes through, held to what its tenant offers and held to the sector
 * it claims, which is the one claim of a registration that is proved somewhere other than in the request.
 */
final readonly class RegistrationUnderThePolicy
{
    public function __construct(
        private ClientMetadataReader $reader,
        private RegistrationHeldToTheTenant $tenantOffer,
        private RegistrationHeldToItsSector $sector,
        private SecretDrawer $secrets,
        private PasswordHasherInterface $hasher,
    ) {
    }

    /**
     * What is kept of a registration is what described the client, from every source that described it and
     * in the order they win (RFC 7591 §3.1.1): a member a statement signed is the registered one, so it is
     * the one the row holds and the one read back from it, or the client would be registered with what its
     * authority said and served with what its caller typed. What the policy of the tenant writes is beside
     * it (`AssignedMembers`) and what a specification defaults is derived, neither being anything a client
     * registered.
     *
     * For a mode that puts nothing in front of the body, this is the body.
     *
     * @param list<ClientMetadataSourceInterface> $sources the one that wins first
     *
     * @return array<string, mixed>
     */
    private static function described(array $sources): array
    {
        $described = [];
        foreach (array_reverse($sources) as $source) {
            $described = [...$described, ...$source->members()];
        }

        return $described;
    }

    /**
     * @param list<ClientMetadataSourceInterface> $inFront what an authorisation puts in front of the members the client sent, empty for a mode that puts nothing there
     * @param array<string, mixed> $members the members the client sent
     * @param ClientRegistrationPolicy|null $policy null for a tenant that has none, which writes nothing on this registration
     * @param ClientSecretInterface|null $kept the secret this client already holds, null at a registration and for a client that holds none
     *
     * @throws UnreadableClientMetadataException when the registration does not hold together, or names
     *                                           something the wiring or the tenant does not offer
     */
    public function read(
        Tenant $tenant,
        string $clientId,
        array $inFront,
        array $members,
        ?ClientRegistrationPolicy $policy,
        ?ClientSecretInterface $kept = null,
    ): KeptRegistration {
        $sent = [...$inFront, new RegisteredMembers($members)];

        // What the policy writes is known only once the method is: it exempts a confidential client from
        // PKCE and never a public one (decision 0017), and the provider assigns a secret exactly when the
        // method proves one (RFC 7591 §3.2.1). One member answers both, and it is read once.
        $method = $this->reader->authenticationMethodOf($clientId, new ClientMetadata([...$sent, new SpecifiedDefaults()]));
        $assigned = new AssignedMembers($policy?->membersWrittenOn($method) ?? []);
        $metadata = new ClientMetadata([...$sent, $assigned, new SpecifiedDefaults()]);

        $drawn = null;
        $secret = null;
        if ($method instanceof SecretKeepingMethodInterface) {
            $secret = $kept !== null && $method->accepts($kept) ? $kept : null;
            if ($secret === null) {
                $drawn = $this->secrets->draw();
                $secret = $method->keep($drawn, $this->hasher);
            }
        }

        $registration = $this->reader->read($clientId, $metadata, $secret !== null);
        $this->tenantOffer->assertHolds($tenant, $registration, $metadata);
        $this->sector->assertHolds($registration, $metadata);

        return new KeptRegistration(self::described($sent), $assigned->members(), $secret, $drawn);
    }
}

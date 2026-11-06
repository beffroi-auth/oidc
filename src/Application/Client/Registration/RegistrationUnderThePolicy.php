<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use function array_reverse;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Oidc\Application\Client\ClientMetadataReader;
use Beffroi\Oidc\Application\Client\Method\SecretKeepingMethodInterface;
use Beffroi\Oidc\Application\Secret\SecretDrawer;
use Beffroi\Oidc\Domain\Client\ClientSecretInterface;
use Beffroi\Oidc\Domain\Client\Metadata\AssignedMembers;
use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadataSourceInterface;
use Beffroi\Oidc\Domain\Client\Metadata\GrantedMembers;
use Beffroi\Oidc\Domain\Client\Metadata\RegisteredMembers;
use Beffroi\Oidc\Domain\Client\Metadata\SpecifiedDefaults;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Beffroi\Oidc\Exception\UnreadableClientMetadataException;

/**
 * RFC 7591 §3.1, RFC 7592 §2.2
 *
 * A creation and a replacement both go through this alone, so an update reaches nothing a registration could not.
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
     * RFC 7591 §3.1.1
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
     * @param list<ClientMetadataSourceInterface> $inFront
     * @param array<string, mixed> $members
     *
     * @throws UnreadableClientMetadataException
     */
    public function read(
        Tenant $tenant,
        string $clientId,
        array $inFront,
        array $members,
        ?ClientRegistrationPolicy $policy,
        ?ClientSecretInterface $kept = null,
        ?GrantedMembers $granted = null,
    ): KeptRegistration {
        $sent = [...$inFront, new RegisteredMembers($members)];

        $registered = new ClientMetadata([...$sent, new SpecifiedDefaults()]);
        $method = $this->reader->authenticationMethodOf($clientId, $registered);
        $assigned = new AssignedMembers($policy?->membersWrittenOn($method, $registered) ?? []);
        $metadata = new ClientMetadata([...$sent, ...($granted === null ? [] : [$granted]), $assigned, new SpecifiedDefaults()]);

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

        return new KeptRegistration(
            self::described($sent),
            $assigned->members(),
            $inFront === [] ? null : self::described($inFront),
            $secret,
            $drawn,
        );
    }
}

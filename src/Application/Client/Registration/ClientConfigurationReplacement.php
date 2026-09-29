<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Registration;

use function array_key_exists;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Client\ClientMetadataReader;
use Heidi\Oidc\Application\Client\Method\SecretKeepingMethodInterface;
use Heidi\Oidc\Domain\Client\ClientRecord;
use Heidi\Oidc\Domain\Client\Metadata\RegisteredMembers;
use Heidi\Oidc\Domain\Client\Registration\ClientInformationResponse;
use Heidi\Oidc\Domain\Client\Registration\RegistrationRequest;
use Heidi\Oidc\Exception\InvalidClientMetadataException;
use Heidi\Oidc\Exception\UnauthorizedClientConfigurationException;
use Heidi\Oidc\Exception\UnreadableClientMetadataException;
use Heidi\Oidc\Port\ClientConfigurationEndpointInterface;
use Heidi\Oidc\Port\ClientRegistrationPolicyInterface;
use Heidi\Oidc\Port\ClientStoreInterface;
use function is_string;
use function sprintf;

/**
 * A client replaces its own registration (RFC 7592 §2.2). **An update is whole and never a patch**: a
 * member the client leaves out is a member it no longer registers, so what is read is a registration and
 * not a difference, and it is read by the very thing a creation is read by
 * (`RegistrationUnderThePolicy`). An update therefore cannot reach what a registration could not: the same
 * wiring, the same policy of the same tenant, the same refusals.
 *
 * Three members of the request are not metadata. §2.2 requires the `client_id`, and it must be the one the
 * URI names: a client may not rename itself, and a request that names another client is refused rather
 * than arbitrated. `client_id_issued_at`, `client_secret_expires_at`, `registration_access_token` and
 * `registration_client_uri` are what the provider assigned, and §2.2 says a request carries none of them.
 * The `client_secret` a client may echo back is compared with what it holds and never read back out of
 * what the provider keeps; one that is not the client's own is refused, as §2.2 requires.
 *
 * What the provider assigned does not change, the identifier, the date it was drawn on and the token the
 * client reads itself with, which is not rotated (§2.3). The secret is the one thing that may: a client
 * that registers a method proving a secret where it held none is handed one, answered once as a
 * registration answers one, and a client that registers a method proving none keeps nothing.
 */
final readonly class ClientConfigurationReplacement
{
    /**
     * RFC 7592 §2.2: what the provider assigned, and what a request therefore does not carry.
     *
     * @var list<string>
     */
    private const array ASSIGNED_BY_THE_PROVIDER = [
        'client_id_issued_at',
        'client_secret_expires_at',
        'registration_access_token',
        'registration_client_uri',
    ];

    /**
     * RFC 7592 §2.2: the identifier the request must name, and the secret it may.
     */
    private const string CLIENT_ID = 'client_id';

    private const string CLIENT_SECRET = 'client_secret';

    public function __construct(
        private ClientConfigurationAccess $access,
        private ClientMetadataReader $reader,
        private ClientRegistrationPolicyInterface $policies,
        private RegistrationUnderThePolicy $registrations,
        private ClientStoreInterface $clients,
        private ClientConfigurationEndpointInterface $endpoints,
    ) {
    }

    /**
     * @throws UnauthorizedClientConfigurationException when the request reads no client of that tenant
     * @throws UnreadableClientMetadataException when the registration does not hold together, which is the
     *                                           400 of RFC 7591 §3.2.2 under the error its subclass names
     */
    public function replace(Tenant $tenant, string $clientId, RegistrationRequest $request): ClientInformationResponse
    {
        $record = $this->access->granted($tenant, $clientId, $request->authorizationHeader);
        $members = $request->members();
        self::assertItNamesItself($record, $members);
        self::assertItWritesNothingTheProviderAssigned($record, $members);
        $this->assertItEchoesItsOwnSecret($record, $members);
        unset($members[self::CLIENT_ID], $members[self::CLIENT_SECRET]);

        $kept = $this->registrations->read(
            $tenant,
            $record->clientId,
            [],
            $members,
            $this->policies->policyFor($tenant),
            $record->secret,
        );
        $record->replaceWith($kept->metadata, $kept->assigned, $kept->secret);
        $this->clients->save($record);

        return new ClientInformationResponse(
            ClientInformationResponse::INFORMED,
            $record,
            $this->endpoints->clientConfigurationFor($tenant, $record->clientId),
            $kept->drawnSecret,
        );
    }

    /**
     * @param array<string, mixed> $members
     *
     * @throws InvalidClientMetadataException
     */
    private static function assertItNamesItself(ClientRecord $record, array $members): void
    {
        $named = $members[self::CLIENT_ID] ?? null;
        if (! is_string($named) || $named !== $record->clientId) {
            throw new InvalidClientMetadataException(
                self::CLIENT_ID,
                self::source(),
                sprintf(
                    'A client replacing its own registration names itself, and the client "%s" is the one this endpoint answers for (RFC 7592 section 2.2).',
                    $record->clientId,
                ),
            );
        }
    }

    /**
     * @param array<string, mixed> $members
     *
     * @throws InvalidClientMetadataException
     */
    private static function assertItWritesNothingTheProviderAssigned(ClientRecord $record, array $members): void
    {
        foreach (self::ASSIGNED_BY_THE_PROVIDER as $member) {
            if (array_key_exists($member, $members)) {
                throw new InvalidClientMetadataException(
                    $member,
                    self::source(),
                    sprintf(
                        'The member "%s" of the client "%s" is what the provider assigned, and a replacement does not carry it (RFC 7592 section 2.2).',
                        $member,
                        $record->clientId,
                    ),
                );
            }
        }
    }

    /**
     * RFC 7592 §2.2: a client may echo back the secret it was handed, and it may echo back no other.
     *
     * @param array<string, mixed> $members
     *
     * @throws InvalidClientMetadataException
     */
    private function assertItEchoesItsOwnSecret(ClientRecord $record, array $members): void
    {
        if (! array_key_exists(self::CLIENT_SECRET, $members)) {
            return;
        }
        $kept = $record->secret;
        $presented = $members[self::CLIENT_SECRET];
        $method = $this->reader->authenticationMethodOf($record->clientId, $record->asRegistered());
        $holds = is_string($presented) && $kept !== null && $method instanceof SecretKeepingMethodInterface && $method->holdsSecret($presented, $kept);
        if (! $holds) {
            throw new InvalidClientMetadataException(
                self::CLIENT_SECRET,
                self::source(),
                sprintf(
                    'The "%s" of the client "%s" is not the secret it holds (RFC 7592 section 2.2).',
                    self::CLIENT_SECRET,
                    $record->clientId,
                ),
            );
        }
    }

    /**
     * @return non-empty-string
     */
    private static function source(): string
    {
        return new RegisteredMembers([])->source();
    }
}

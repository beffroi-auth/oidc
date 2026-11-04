<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use function array_key_exists;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Client\ClientMetadataReader;
use Beffroi\Oidc\Application\Client\Method\SecretKeepingMethodInterface;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Client\Metadata\RegisteredMembers;
use Beffroi\Oidc\Domain\Client\Registration\ClientInformationResponse;
use Beffroi\Oidc\Domain\Client\Registration\RegistrationRequest;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use Beffroi\Oidc\Exception\UnauthorizedClientConfigurationException;
use Beffroi\Oidc\Exception\UnreadableClientMetadataException;
use Beffroi\Oidc\Port\ClientConfigurationEndpointInterface;
use Beffroi\Oidc\Port\ClientRegistrationPolicyInterface;
use Beffroi\Oidc\Port\ClientStoreInterface;
use function is_string;
use function sprintf;

/**
 * RFC 7592 §2.2
 *
 * A signed statement's members still outrank the replacement: an attested client keeps what its authority signed.
 */
final readonly class ClientConfigurationReplacement
{
    /**
     * @var list<string>
     */
    private const array ASSIGNED_BY_THE_PROVIDER = [
        'client_id_issued_at',
        'client_secret_expires_at',
        'registration_access_token',
        'registration_client_uri',
    ];

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
     * @throws UnauthorizedClientConfigurationException
     * @throws UnreadableClientMetadataException
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
            $record->attestation(),
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

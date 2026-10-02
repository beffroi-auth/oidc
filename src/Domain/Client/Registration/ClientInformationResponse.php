<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Registration;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use SensitiveParameter;

/**
 * What the provider answers a client about itself: the registration response of RFC 7591 §3.2.1 and the
 * client information response of RFC 7592 §3 are the same body, so they are one thing here. The
 * identifier the provider drew, the date it drew it on, the metadata it registered, and where that client
 * reads, replaces and deletes itself.
 *
 * The metadata answered is the metadata the provider kept, which is what the client sent: a member it
 * sent and this provider ignored does not exist, since a member nobody reads is refused rather than kept.
 *
 * **A secret is answered once, at the moment the provider assigns one, and never again**: what the
 * provider keeps of it is the shape the registered method verifies against, and for the method that
 * receives one that shape is a hash nobody can read back. So a registration answers the secret it drew
 * and a read answers none (RFC 7592 §2.1), and a replacement answers one only when it registered a
 * method that proves one where the client held none. "client_secret_expires_at" is required whenever a
 * secret is answered, and 0 is what says that the secret does not expire (RFC 7591 §3.2.1).
 *
 * **The registration access token is answered once too**, for the same reason: what the row keeps is its
 * digest. §2.3 permits rotating it on every answer and does not require it, so a read answers the URI
 * and not the token, and the client keeps the one it was handed.
 */
final readonly class ClientInformationResponse
{
    public const string CONTENT_TYPE = 'application/json';

    /**
     * RFC 7591 §3.2.1: the status of a client that has just been registered.
     */
    public const int REGISTERED = 201;

    /**
     * RFC 7592 §3: the status of a client answered about itself.
     */
    public const int INFORMED = 200;

    /**
     * RFC 7591 §3.2.1, RFC 7592 §3, and the refusals of both.
     */
    public const array HEADERS = [
        'Cache-Control' => 'no-cache, no-store',
        'Pragma' => 'no-cache',
    ];

    /**
     * RFC 7591 §3.2.1: what says that a secret does not expire.
     */
    private const int NEVER = 0;

    /**
     * @param string $registrationClientUri where this client reads, replaces and deletes itself (RFC 7592 §3)
     * @param string|null $secret the value the provider drew, answered this once and kept only in the shape the registered method verifies against; null when nothing was drawn
     * @param string|null $registrationAccessToken the value the provider drew for that URI, answered this once; null when nothing was drawn
     */
    public function __construct(
        public int $statusCode,
        public ClientRecord $record,
        public string $registrationClientUri,
        #[SensitiveParameter]
        public ?string $secret = null,
        #[SensitiveParameter]
        public ?string $registrationAccessToken = null,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function parameters(): array
    {
        $parameters = [
            'client_id' => $this->record->clientId,
            'client_id_issued_at' => $this->record->issuedAt->getTimestamp(),
        ];
        if ($this->secret !== null) {
            $parameters['client_secret'] = $this->secret;
            $parameters['client_secret_expires_at'] = $this->record->secretExpiresAt instanceof DateTimeImmutable
                ? $this->record->secretExpiresAt->getTimestamp()
                : self::NEVER;
        }
        if ($this->registrationAccessToken !== null) {
            $parameters['registration_access_token'] = $this->registrationAccessToken;
        }
        $parameters['registration_client_uri'] = $this->registrationClientUri;

        return $parameters + $this->record->metadata;
    }
}

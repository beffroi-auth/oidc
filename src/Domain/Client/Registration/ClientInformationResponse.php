<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Registration;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use SensitiveParameter;

/**
 * RFC 7591 §3.2.1, RFC 7592 §3
 */
final readonly class ClientInformationResponse
{
    public const string CONTENT_TYPE = 'application/json';

    public const int REGISTERED = 201;

    public const int INFORMED = 200;

    public const array HEADERS = [
        'Cache-Control' => 'no-cache, no-store',
        'Pragma' => 'no-cache',
    ];

    private const int NEVER = 0;

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

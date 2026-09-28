<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client\Registration;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Client\ClientRecord;
use SensitiveParameter;

/**
 * The answer of the registration endpoint to a client it registered (RFC 7591 §3.2.1): a 201 carrying
 * the metadata the provider registered, the identifier it drew and the date it drew it on, and the
 * secret it assigned when the method the client registered needs one. Never cached, the secret being
 * answered once and never again.
 *
 * The metadata answered is the metadata the provider kept, which is what the client sent: a member it
 * sent and this provider ignored does not exist, since a member nobody reads is refused rather than
 * kept, and a member the provider assigned is one of the two dates below.
 *
 * "client_secret_expires_at" is required whenever a secret is answered, and 0 is what says that the
 * secret does not expire (§3.2.1), which is what every secret this provider assigns does today.
 */
final readonly class ClientRegistrationResponse
{
    public const string CONTENT_TYPE = 'application/json';

    public const int STATUS_CODE = 201;

    /**
     * RFC 7591 §3.2.1, for the errors of §3.2.2 as well.
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
     * @param string|null $secret the value the provider drew, answered this once and kept as nothing but the shape the registered method verifies against; null for a client whose method proves none
     */
    public function __construct(
        public ClientRecord $record,
        #[SensitiveParameter]
        public ?string $secret = null,
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

        return $parameters + $this->record->metadata;
    }
}

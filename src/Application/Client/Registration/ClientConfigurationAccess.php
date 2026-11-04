<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\UnauthorizedClientConfigurationException;
use Beffroi\Oidc\Port\ClientStoreInterface;
use function preg_match;
use SensitiveParameter;

/**
 * RFC 7592 §2.3
 *
 * Looked up by the URI's identifier, then the token digest compared in constant time; every refusal is the same.
 */
final readonly class ClientConfigurationAccess
{
    /**
     * RFC 6750 §2.1, RFC 9110 §11.6.1
     */
    private const string CREDENTIALS = '/^Bearer[ ]+([^ ]+)$/i';

    public function __construct(
        private ClientStoreInterface $clients,
    ) {
    }

    /**
     * @throws UnauthorizedClientConfigurationException
     */
    public function granted(Tenant $tenant, string $clientId, #[SensitiveParameter] ?string $authorizationHeader): ClientRecord
    {
        $presented = self::presented($authorizationHeader);
        $record = $presented === null ? null : $this->clients->findRecord($tenant, $clientId);
        if ($presented === null || $record === null || ! $record->belongsTo($tenant) || ! $record->isReadWith(DrawnSecret::digestOf($presented))) {
            throw new UnauthorizedClientConfigurationException();
        }

        return $record;
    }

    private static function presented(#[SensitiveParameter] ?string $header): ?string
    {
        if ($header === null || preg_match(self::CREDENTIALS, $header, $credentials) !== 1) {
            return null;
        }

        return $credentials[1];
    }
}

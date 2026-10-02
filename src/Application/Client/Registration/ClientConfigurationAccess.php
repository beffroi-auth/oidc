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
 * Which client a request at a client configuration endpoint is for (RFC 7592 §2.3): the one the URI names,
 * and only if the request carries the registration access token that client was handed.
 *
 * The token is a credential of **that one client for that one URI**. It is not the client's secret, it is
 * not an access token of this provider, and it opens nothing else: nothing but this reads it, so there is
 * no endpoint it could open. A token drawn for another client is refused here, as §2.3 requires, and with
 * the same answer as a value nobody was ever handed: the store answers by the identifier the URI names,
 * and the digest is then compared in constant time.
 *
 * A client the store no longer holds is the same refusal, which is what a client that has just deleted
 * itself sees when it comes back.
 */
final readonly class ClientConfigurationAccess
{
    /**
     * RFC 6750 §2.1 and RFC 9110 §11.6.1: the scheme is compared without regard to case, and what follows
     * it is the credential. A credential of another shape is one this provider never drew.
     */
    private const string CREDENTIALS = '/^Bearer[ ]+([^ ]+)$/i';

    public function __construct(
        private ClientStoreInterface $clients,
    ) {
    }

    /**
     * @throws UnauthorizedClientConfigurationException when the request reads no client of that tenant
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

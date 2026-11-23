<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Interaction;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Consent\SharedIdentity;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Interaction\ThirdPartyInitiatedLogin;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use Beffroi\Oidc\Port\SubjectIdentifierResolverInterface;

/**
 * OIDC Core §4
 *
 * An unknown client and one with no "initiate_login_uri" are one answer, so no caller learns which clients exist, and
 * the hint names only a person the client may be told of.
 */
final readonly class ThirdPartyInitiatedLoginHandler
{
    public function __construct(
        private ClientRepositoryInterface $clients,
        private SubjectIdentifierResolverInterface $subjects,
        private SharedIdentity $sharedIdentity,
    ) {
    }

    /**
     * @throws InvalidArgumentException when the sector of the client's kind of subject identifier cannot be read
     */
    public function handle(
        Tenant $tenant,
        string $clientId,
        ?User $user = null,
        ?string $targetLinkUri = null,
    ): ?ThirdPartyInitiatedLogin {
        $client = $this->clients->findByClientId($tenant, $clientId);
        if ($client === null || $client->registration->initiateLoginUri === null) {
            return null;
        }

        return new ThirdPartyInitiatedLogin(
            $client->registration->initiateLoginUri,
            $tenant->issuer,
            $user === null || ! $this->sharedIdentity->isSharedWith($user, $client) ? null : $this->subjects->resolve($user, $client),
            self::registered($client, $targetLinkUri),
        );
    }

    /**
     * RFC 6749 §3.1.2.3
     *
     * The registered object is returned, so a value that came from the request never leaves this provider.
     */
    private static function registered(Client $client, ?string $targetLinkUri): ?RedirectUri
    {
        if ($targetLinkUri === null || $targetLinkUri === '') {
            return null;
        }
        foreach ($client->registration->redirectUris as $redirectUri) {
            if ($redirectUri->value === $targetLinkUri) {
                return $redirectUri;
            }
        }

        return null;
    }
}

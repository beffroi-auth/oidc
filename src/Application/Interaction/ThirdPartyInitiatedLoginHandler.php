<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Interaction;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Interaction\ThirdPartyInitiatedLogin;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use Beffroi\Oidc\Port\SubjectIdentifierResolverInterface;

/**
 * A login this provider begins at a client (OIDC Core §4): a caller names a client of the tenant, and
 * this answers where that client is to be sent the browser, or nothing at all.
 *
 * A caller names a client and never a destination. The two ways there is nothing to answer, a client no
 * tenant of this name holds and a client that registered no "initiate_login_uri", are one answer and not
 * two, so that whoever asks learns which clients exist no more than whoever asks for an interaction that
 * is not theirs learns whose it is.
 *
 * Nothing here requires the browser to hold a session. The client is about to make an authorization
 * request, and that request asks for whatever login it needs; a provider that demanded one first would
 * ask for it twice and would refuse the case §4 exists for, a link followed by somebody who has not
 * signed in yet. A session that is open is what the hint is drawn from, and its absence takes the hint
 * away rather than the redirection.
 */
final readonly class ThirdPartyInitiatedLoginHandler
{
    public function __construct(
        private ClientRepositoryInterface $clients,
        private SubjectIdentifierResolverInterface $subjects,
    ) {
    }

    /**
     * @param string $clientId the client to begin a login at, as the caller named it
     * @param User|null $user whoever the browser is signed in as, null for a browser holding no session
     * @param string|null $targetLinkUri where the caller asks the client to land the user, carried only
     *                                   when that client registered it
     *
     * @throws InvalidArgumentException when the client registered a kind of subject identifier whose
     *                                  sector cannot be read, which its registration refuses
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
            $user === null ? null : $this->subjects->resolve($user, $client),
            self::registered($client, $targetLinkUri),
        );
    }

    /**
     * The registered redirection URI the caller named, byte for byte (RFC 6749 §3.1.2.3), and null for
     * anything else: what is carried on is the object the registration holds, so a value that came from
     * a request never leaves this provider. A caller that names none, or names one of another client, is
     * answered the redirection without a landing page rather than a refusal; §4 makes it optional and
     * the client knows where to land its own users.
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

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\EndSession;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Authorization\IdTokenHintVerifier;
use Heidi\Oidc\Application\Request\RequestParameters;
use Heidi\Oidc\Domain\Authorization\IdTokenHint;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\EndSession\EndSessionRequest;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Port\ClientRepositoryInterface;

/**
 * Reads a logout request (RP-Initiated Logout §2): the hint identifies the client, client_id must be
 * in its audience, post_logout_redirect_uri is honoured only for an identified client (§3). No error
 * is redirectable (§4). A hint the provider cannot verify today (a retired key) identifies no client
 * and marks the request so that the handler asks the user (§2, §6).
 */
final readonly class EndSessionRequestParser
{
    public function __construct(
        private ClientRepositoryInterface $clients,
        private IdTokenHintVerifier $idTokenHints,
    ) {
    }

    /**
     * @param array<string, mixed> $parameters
     *
     * @throws OAuth2Exception never redirectable
     */
    public function parse(Tenant $tenant, array $parameters): EndSessionRequest
    {
        $request = RequestParameters::of($parameters);
        $idTokenHint = $request->compactJws('id_token_hint');
        $hint = null;
        $invalidHint = false;
        if ($idTokenHint !== null) {
            try {
                $hint = $this->idTokenHints->read($tenant, $idTokenHint, false);
            } catch (InvalidRequestException) {
                $invalidHint = true;
            }
        }
        $client = $this->client($tenant, $hint, $request->optional('client_id'));
        $postLogoutRedirectUri = self::postLogoutRedirectUri($client, $request->optional('post_logout_redirect_uri'), $invalidHint);

        return new EndSessionRequest(
            $tenant,
            $client,
            $hint,
            $postLogoutRedirectUri,
            $request->state(),
            $request->text('logout_hint'),
            $request->uiLocales(),
            $invalidHint,
        );
    }

    /**
     * §2: client_id, or else the first audience of the hint that is a client of the tenant.
     */
    private function client(Tenant $tenant, ?IdTokenHint $hint, ?string $clientId): ?Client
    {
        if ($clientId !== null) {
            if ($hint !== null && ! $hint->isFor($clientId)) {
                throw new InvalidRequestException('The client_id parameter is not an audience of the id_token_hint parameter.');
            }

            return $this->clients->findByClientId($tenant, $clientId) ?? throw new InvalidRequestException('The client is unknown.');
        }
        if ($hint === null) {
            return null;
        }
        foreach ($hint->audiences as $audience) {
            $client = $this->clients->findByClientId($tenant, $audience);
            if ($client !== null) {
                return $client;
            }
        }

        throw new InvalidRequestException('The id_token_hint parameter is not an ID token issued to a client of this provider.');
    }

    /**
     * §3: only a URI the client registered byte for byte. Without a client the URI is a fault of the
     * request, unless the hint could not be verified: it is then dropped and the user asked.
     */
    private static function postLogoutRedirectUri(?Client $client, ?string $postLogoutRedirectUri, bool $invalidHint): ?RedirectUri
    {
        if ($postLogoutRedirectUri === null) {
            return null;
        }
        if ($client === null) {
            if ($invalidHint) {
                return null;
            }

            throw new InvalidRequestException('The post_logout_redirect_uri parameter requires id_token_hint or client_id to identify the client.');
        }
        if (! $client->registration->hasPostLogoutRedirectUri($postLogoutRedirectUri)) {
            throw new InvalidRequestException('The post_logout_redirect_uri parameter is not registered for this client.');
        }

        return new RedirectUri($postLogoutRedirectUri);
    }
}

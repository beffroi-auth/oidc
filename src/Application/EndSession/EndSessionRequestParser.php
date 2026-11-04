<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\EndSession;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Authorization\IdTokenHintVerifier;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\Authorization\IdTokenHint;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\EndSession\EndSessionRequest;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Port\ClientRepositoryInterface;

/**
 * RP-Initiated Logout §2, §4
 *
 * A hint that cannot be verified (a retired key) is no error: it identifies no client and the user is asked.
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
     * RP-Initiated Logout §3
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

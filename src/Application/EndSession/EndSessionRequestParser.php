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
 * Reads a logout request (OIDC RP-Initiated Logout 1.0 §2) from its parameters, sent by GET in the
 * query or by POST in the form, which the integration hands over as one map. The hint is verified
 * first, because it is what identifies the client when client_id is absent; client_id, when present,
 * must match its audience (§2); post_logout_redirect_uri is honoured only for an identified client
 * and only when it registered that exact URI (§3). A failure is invalid_request, shown to the user:
 * §4 forbids any redirection once the request is found wrong, so no error is ever redirectable here.
 *
 * Every parameter is read as a single string: a repeated or nested parameter is refused, a parameter
 * without a value is treated as omitted, an unknown parameter is ignored (RequestParameters).
 */
final readonly class EndSessionRequestParser
{
    public function __construct(
        private ClientRepositoryInterface $clients,
        private IdTokenHintVerifier $idTokenHints,
    ) {
    }

    /**
     * @param array<string, mixed> $parameters the query or form parameters of the request
     *
     * @throws OAuth2Exception never redirectable: the error is shown to the user
     */
    public function parse(Tenant $tenant, array $parameters): EndSessionRequest
    {
        $idTokenHint = RequestParameters::compactJws($parameters, 'id_token_hint', false);
        $hint = $idTokenHint === null ? null : $this->idTokenHints->read($tenant, $idTokenHint, false);
        $client = $this->client($tenant, $hint, RequestParameters::single($parameters, 'client_id', false));
        $postLogoutRedirectUri = self::postLogoutRedirectUri($client, RequestParameters::single($parameters, 'post_logout_redirect_uri', false));

        return new EndSessionRequest(
            $tenant,
            $client,
            $hint,
            $postLogoutRedirectUri,
            RequestParameters::state($parameters, false),
            RequestParameters::text($parameters, 'logout_hint', false),
            RequestParameters::uiLocales($parameters, false),
        );
    }

    /**
     * §2: the client is the one client_id names, which must then be an audience of the hint; without
     * client_id, the first audience of the hint that is a client of the tenant; without either, none.
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
     * §3: no redirection without a client to check the URI against, and none to a URI the client did
     * not register byte for byte.
     */
    private static function postLogoutRedirectUri(?Client $client, ?string $postLogoutRedirectUri): ?RedirectUri
    {
        if ($postLogoutRedirectUri === null) {
            return null;
        }
        if ($client === null) {
            throw new InvalidRequestException('The post_logout_redirect_uri parameter requires id_token_hint or client_id to identify the client.');
        }
        if (! $client->hasPostLogoutRedirectUri($postLogoutRedirectUri)) {
            throw new InvalidRequestException('The post_logout_redirect_uri parameter is not registered for this client.');
        }

        return new RedirectUri($postLogoutRedirectUri);
    }
}

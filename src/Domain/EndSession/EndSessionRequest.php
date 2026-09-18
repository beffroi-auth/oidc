<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\EndSession;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Authorization\IdTokenHint;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Exception\InvalidArgumentException;

/**
 * A logout request that passed validation (OIDC RP-Initiated Logout 1.0 §2, architecture §4.9): the
 * hint verified and naming a client of the tenant, the client the one the hint or client_id names, the
 * post_logout_redirect_uri one that client registered. Everything the handler needs is here, typed;
 * nothing is read from the raw parameters again. A request may name no client at all: a logout link
 * without parameters is a valid request, it just cannot redirect anywhere afterwards (§3). A request may
 * also carry a hint the provider could not verify (signed by a retired key, or by nobody it knows): the
 * hint is then absent here and the request says so, for the handler to ask the user (§2, §6).
 */
final readonly class EndSessionRequest
{
    /**
     * @param Client|null $client the client the request identifies, by the audience of the hint or by client_id
     * @param IdTokenHint|null $idTokenHint the verified hint, issued to the client
     * @param RedirectUri|null $postLogoutRedirectUri registered on the client, byte for byte
     * @param string|null $state echoed as is in the redirect (§2 "state")
     * @param string|null $logoutHint a hint about the end user (§2 "logout_hint"), shown to nobody but the confirmation page
     * @param list<string> $uiLocales preferred languages, most preferred first (§2 "ui_locales")
     * @param bool $invalidIdTokenHint whether the request carried an id_token_hint this provider could not verify, which identifies no client and proves no session
     */
    public function __construct(
        public Tenant $tenant,
        public ?Client $client,
        public ?IdTokenHint $idTokenHint,
        public ?RedirectUri $postLogoutRedirectUri,
        public ?string $state = null,
        public ?string $logoutHint = null,
        public array $uiLocales = [],
        public bool $invalidIdTokenHint = false,
    ) {
        if ($idTokenHint !== null && $invalidIdTokenHint) {
            throw new InvalidArgumentException('A logout request carries a verified id_token_hint or an invalid one, not both.');
        }
        if ($client !== null && ! $client->belongsTo($tenant)) {
            throw new InvalidArgumentException('A logout request names a client of its own tenant.');
        }
        if ($idTokenHint !== null && ($client === null || ! $idTokenHint->isFor($client->clientId))) {
            throw new InvalidArgumentException('The client of a logout request is one the id_token_hint was issued to.');
        }
        if ($postLogoutRedirectUri !== null && ($client === null || ! $client->hasPostLogoutRedirectUri((string) $postLogoutRedirectUri))) {
            throw new InvalidArgumentException('A post_logout_redirect_uri is one the client registered (OIDC RP-Initiated Logout 1.0 §3).');
        }
        if ($state === '') {
            throw new InvalidArgumentException('The state of a logout request is either absent or non-empty.');
        }
    }

    /**
     * Where to send the user agent after the logout, when the client asked and may be honoured (§3).
     */
    public function redirect(): ?PostLogoutRedirect
    {
        if ($this->postLogoutRedirectUri === null) {
            return null;
        }

        return new PostLogoutRedirect($this->postLogoutRedirectUri, $this->state);
    }
}

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use function array_any;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Scope\Scope;
use function in_array;

/**
 * An authorization request that passed both stages of validation (RFC 6749 §4.1.1, OIDC Core §3.1.2.1,
 * architecture §4.2): the client and the redirect URI are the registered ones, the response type is
 * "code", the scope contains "openid", the PKCE challenge is S256 or, for a client that does not require
 * one (decision 0008), absent. Everything the interaction (§4.3) and
 * the authorization code (§4.4) need is here, already typed; nothing is read from the raw parameters
 * again.
 */
final readonly class AuthorizationRequest
{
    /**
     * @param RedirectUri $redirectUri the one the client presented, byte for byte equal to a registered one
     * @param list<Scope> $scopes contains "openid", every scope is allowed to the client
     * @param CodeChallenge|null $codeChallenge null only when the client does not require PKCE and sent none
     * @param string|null $state echoed as is in the response (RFC 6749 §4.1.2)
     * @param string|null $nonce bound to the ID token (OIDC Core §3.1.2.1, §3.1.3.7 step 11)
     * @param list<Prompt> $prompts OIDC Core §3.1.2.1 "prompt"
     * @param int|null $maxAge seconds since the last authentication the client tolerates (OIDC Core §3.1.2.1 "max_age")
     * @param string|null $loginHint a hint about the end user, shown to nobody but the login form
     * @param list<string> $uiLocales preferred languages, most preferred first (OIDC Core §3.1.2.1 "ui_locales")
     * @param list<string> $acrValues requested authentication context classes, in order of preference
     * @param string|null $idTokenHint a compact JWS the interaction verifies before trusting (OIDC Core §3.1.2.1 "id_token_hint")
     * @param ClaimsRequest|null $claims OIDC Core §5.5
     */
    public function __construct(
        public Client $client,
        public RedirectUri $redirectUri,
        public array $scopes,
        public ?CodeChallenge $codeChallenge,
        public ?string $state = null,
        public ?string $nonce = null,
        public array $prompts = [],
        public ?int $maxAge = null,
        public ?string $loginHint = null,
        public array $uiLocales = [],
        public array $acrValues = [],
        public ?Display $display = null,
        public ?string $idTokenHint = null,
        public ?ClaimsRequest $claims = null,
        public ResponseMode $responseMode = ResponseMode::Query,
    ) {
    }

    /**
     * Where an error raised from now on is sent (RFC 6749 §4.1.2.1, second stage).
     */
    public function redirectTarget(): RedirectTarget
    {
        return new RedirectTarget($this->client, $this->redirectUri, $this->state);
    }

    public function hasScope(Scope $scope): bool
    {
        return array_any($this->scopes, static fn (Scope $granted): bool => $granted->equals($scope));
    }

    public function hasPrompt(Prompt $prompt): bool
    {
        return in_array($prompt, $this->prompts, true);
    }
}

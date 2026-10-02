<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use function in_array;

/**
 * An authorization request that passed both stages of validation (RFC 6749 §4.1.1, OIDC Core §3.1.2.1,
 * architecture §4.2), already typed; nothing is read from the raw parameters again.
 */
final readonly class AuthorizationRequest
{
    /**
     * @param CodeChallenge|null $codeChallenge null only when the client does not require PKCE and sent none
     * @param list<Prompt> $prompts
     * @param list<string> $uiLocales most preferred first
     * @param list<string> $acrValues in order of preference
     * @param string|null $idTokenHint a compact JWS, verified by the interaction
     * @param KeyConfirmation|null $dpopKey the key the client asks the code to be reserved for ("dpop_jkt", RFC 9449 §10), null when it asks for none
     * @param ResourceIndicators|null $resources the resources the tokens are asked for ("resource", RFC 8707 §2.1), null when the request names none
     * @param string $responseMode the wired mode the answer is delivered in, resolved by the parser against what the integration serves (RedirectTarget)
     * @param AuthorizationDetails|null $authorizationDetails what the request asks for beyond its scopes ("authorization_details", RFC 9396 §2), null when it asks for none
     */
    public function __construct(
        public Client $client,
        public RedirectUri $redirectUri,
        public Scopes $scopes,
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
        public string $responseMode = ResponseModeNames::DEFAULT,
        public ?KeyConfirmation $dpopKey = null,
        public ?ResourceIndicators $resources = null,
        public ?AuthorizationDetails $authorizationDetails = null,
    ) {
    }

    public function redirectTarget(): RedirectTarget
    {
        return new RedirectTarget($this->client, $this->redirectUri, $this->state, $this->responseMode);
    }

    public function hasPrompt(Prompt $prompt): bool
    {
        return in_array($prompt, $this->prompts, true);
    }
}

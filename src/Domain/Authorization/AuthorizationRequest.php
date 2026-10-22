<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

use Beffroi\Core\Domain\PersonalData\ClassifiedFieldsInterface;
use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use Beffroi\Core\Domain\PersonalData\Sealed;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use DateTimeImmutable;
use function in_array;
use function sprintf;

/**
 * An authorization request that passed both stages of validation (RFC 6749 §4.1.1, OIDC Core §3.1.2.1,
 * architecture §4.2), already typed; nothing is read from the raw parameters again.
 */
final readonly class AuthorizationRequest implements ClassifiedFieldsInterface
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

    /**
     * OIDC Core §3.1.2.1 max_age: whether the latest proof of the session is older than the request allows, its
     * "auth_time" plus max_age seconds before now; never when the request names no max_age. The login page asks for a
     * new login on it (AuthenticationRequirement), and the service provider of a tenant asks an upstream identity
     * provider for one (beffroi/saml, spec/saml.md S-49).
     */
    public function maxAgeExceededBy(AuthenticationSession $session, DateTimeImmutable $now): bool
    {
        return $this->maxAge !== null && $session->authenticatedAt()->modify(sprintf('+%d seconds', $this->maxAge)) < $now;
    }

    /**
     * The two hints a client may send name the person it asks for, and they are sealed under the family of the one
     * entity that embeds this object. An embeddable fixes the type of each of its fields once for the whole model,
     * so a second entity embedding it would seal them into the scope of another table, which the walk of the
     * schema refuses (Sealed).
     *
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            'redirectUri' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'scopes' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'resources' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'authorizationDetails' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'codeChallenge' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'state' => new NoPersonalDatum(Reason::DRAWN_BY_THE_CLIENT),
            'nonce' => new NoPersonalDatum(Reason::DRAWN_BY_THE_CLIENT),
            'prompts' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'maxAge' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'loginHint' => new Sealed('interaction'),
            'uiLocales' => new NoPersonalDatum(Reason::THE_LANGUAGE_ASKED_FOR),
            'acrValues' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'display' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'idTokenHint' => new Sealed('interaction'),
            'claims' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'responseMode' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'dpopKey' => new NoPersonalDatum(Reason::WHAT_A_TOKEN_IS_BOUND_TO),
        ];
    }
}

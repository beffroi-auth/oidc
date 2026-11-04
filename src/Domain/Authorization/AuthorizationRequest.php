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
 * RFC 6749 §4.1.1, OIDC Core §3.1.2.1
 */
final readonly class AuthorizationRequest implements ClassifiedFieldsInterface
{
    /**
     * @param CodeChallenge|null $codeChallenge null only when the client does not require PKCE and sent none
     * @param list<Prompt> $prompts
     * @param list<string> $uiLocales most preferred first
     * @param list<string> $acrValues in order of preference
     * @param string|null $idTokenHint a compact JWS, verified by the interaction
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
     * OIDC Core §3.1.2.1
     */
    public function maxAgeExceededBy(AuthenticationSession $session, DateTimeImmutable $now): bool
    {
        return $this->maxAge !== null && $session->authenticatedAt()->modify(sprintf('+%d seconds', $this->maxAge)) < $now;
    }

    /**
     * Only one entity may embed this object: the hints it seals belong to the family of that entity.
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

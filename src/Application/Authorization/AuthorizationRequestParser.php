<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Authorization;

use function array_any;
use function count;
use function explode;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Request\RequestParameters;
use Heidi\Oidc\Domain\Authorization\AuthorizationRequest;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Authorization\CodeChallenge;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Domain\Authorization\Display;
use Heidi\Oidc\Domain\Authorization\Prompt;
use Heidi\Oidc\Domain\Authorization\RedirectTarget;
use Heidi\Oidc\Domain\Authorization\ResponseMode;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\InvalidScopeException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Exception\RequestNotSupportedException;
use Heidi\Oidc\Exception\RequestUriNotSupportedException;
use Heidi\Oidc\Exception\UnsupportedResponseTypeException;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use function in_array;
use function preg_match;

/**
 * Reads an authorization request (RFC 6749 §4.1.1, OIDC Core §3.1.2.1) in the two stages of RFC 6749
 * §4.1.2.1: the client and the redirect URI first, whose failures are never redirected; everything else
 * then, whose failures go back to the client with "state" and "iss".
 */
final readonly class AuthorizationRequestParser
{
    /**
     * OIDC Core §3.1.2.1: seconds, bounded to a PHP integer.
     */
    private const string MAX_AGE_PATTERN = '/^(?:0|[1-9][0-9]{0,17})$/D';

    /**
     * OIDC Core §2 "acr": printable ASCII without space.
     */
    private const string ACR_VALUE_PATTERN = '/^[\x21-\x7E]+$/D';

    public function __construct(
        private ClientRepositoryInterface $clients,
    ) {
    }

    /**
     * First stage (RFC 6749 §4.1.2.1, §3.1.2.3): the client, the redirect URI byte for byte, the state.
     *
     * @param array<string, mixed> $parameters
     *
     * @throws OAuth2Exception never redirectable
     */
    public function redirectTarget(Tenant $tenant, array $parameters): RedirectTarget
    {
        $clientId = RequestParameters::single($parameters, 'client_id', false);
        if ($clientId === null) {
            throw new InvalidRequestException('The client_id parameter is missing.');
        }
        $client = $this->clients->findByClientId($tenant, $clientId);
        if ($client === null) {
            throw new InvalidRequestException('The client is unknown.');
        }
        $redirectUri = RequestParameters::single($parameters, 'redirect_uri', false);
        if ($redirectUri === null) {
            throw new InvalidRequestException('The redirect_uri parameter is missing.');
        }
        if (! $client->hasRedirectUri($redirectUri)) {
            throw new InvalidRequestException('The redirect_uri parameter is not registered for this client.');
        }
        return new RedirectTarget($client, new RedirectUri($redirectUri), RequestParameters::state($parameters, false));
    }

    /**
     * Second stage (OIDC Core §3.1.2.2, RFC 7636 §4.4, architecture §4.2): everything else. Neither form
     * of request object is served (OIDC Core §6).
     *
     * @param array<string, mixed> $parameters
     *
     * @throws OAuth2Exception always redirectable
     */
    public function parse(RedirectTarget $target, array $parameters): AuthorizationRequest
    {
        if (RequestParameters::isPresent($parameters, 'request')) {
            throw new RequestNotSupportedException('Request objects are not supported.');
        }
        if (RequestParameters::isPresent($parameters, 'request_uri')) {
            throw new RequestUriNotSupportedException('Request URIs are not supported.');
        }

        $responseType = RequestParameters::single($parameters, 'response_type', true);
        if ($responseType === null) {
            throw new InvalidRequestException('The response_type parameter is missing.', true);
        }
        if ($responseType !== 'code') {
            throw new UnsupportedResponseTypeException('Only the code response type is supported.');
        }

        $responseMode = RequestParameters::single($parameters, 'response_mode', true);
        if ($responseMode !== null && $responseMode !== ResponseMode::Query->value) {
            throw new InvalidRequestException('Only the query response mode is supported.', true);
        }

        $scopes = $this->scopes($target, RequestParameters::single($parameters, 'scope', true));
        $codeChallenge = self::codeChallenge($target->client, RequestParameters::single($parameters, 'code_challenge', true), RequestParameters::single($parameters, 'code_challenge_method', true));

        $nonce = RequestParameters::text($parameters, 'nonce', true);
        $prompts = self::prompts(RequestParameters::single($parameters, 'prompt', true));
        $maxAge = RequestParameters::single($parameters, 'max_age', true);
        if ($maxAge !== null && preg_match(self::MAX_AGE_PATTERN, $maxAge) !== 1) {
            throw new InvalidRequestException('The max_age parameter must be a non-negative integer.', true);
        }
        $loginHint = RequestParameters::text($parameters, 'login_hint', true);
        $uiLocales = RequestParameters::uiLocales($parameters, true);
        $acrValues = RequestParameters::list($parameters, 'acr_values', self::ACR_VALUE_PATTERN, 'The acr_values parameter must be a space-separated list of printable ASCII values.', true);
        $display = self::display(RequestParameters::single($parameters, 'display', true));
        $idTokenHint = RequestParameters::compactJws($parameters, 'id_token_hint', true);
        $claims = self::claims(RequestParameters::single($parameters, 'claims', true));

        return new AuthorizationRequest(
            $target->client,
            $target->redirectUri,
            $scopes,
            $codeChallenge,
            $target->state,
            $nonce,
            $prompts,
            $maxAge === null ? null : (int) $maxAge,
            $loginHint,
            $uiLocales,
            $acrValues,
            $display,
            $idTokenHint,
            $claims,
            ResponseMode::Query,
        );
    }

    /**
     * RFC 6749 §3.3, OIDC Core §3.1.2.2 step 3: contains "openid", every token allowed to the client.
     *
     * @return list<Scope>
     */
    private function scopes(RedirectTarget $target, ?string $scope): array
    {
        if ($scope === null) {
            throw new InvalidRequestException('The scope parameter is missing.', true);
        }
        try {
            $scopes = Scope::parseList($scope);
        } catch (InvalidArgumentException) {
            throw new InvalidScopeException('The scope parameter is not a space-separated list of scope tokens (RFC 6749 section 3.3).', true);
        }
        foreach ($scopes as $candidate) {
            if (! $target->client->allowsScope($candidate)) {
                throw new InvalidScopeException('The requested scope is not allowed for this client.', true);
            }
        }
        if (! array_any($scopes, static fn (Scope $kept): bool => $kept->equals(Scope::openid()))) {
            throw new InvalidScopeException('The scope parameter must contain openid (OIDC Core section 3.1.2.1).', true);
        }

        return $scopes;
    }

    /**
     * RFC 7636 §4.3, §4.4.1: S256 only (decision 0006). A client exempted by decision 0008 may send no
     * challenge; one it sends is checked like any other (RFC 9700 §2.1.1).
     */
    private static function codeChallenge(Client $client, ?string $challenge, ?string $method): ?CodeChallenge
    {
        if ($challenge === null && $method === null && ! $client->requiresPkce) {
            return null;
        }
        if ($challenge === null) {
            throw new InvalidRequestException('The code_challenge parameter is missing (RFC 7636 section 4.3).', true);
        }
        if ($method !== CodeChallengeMethod::S256->value) {
            throw new InvalidRequestException('The code_challenge_method parameter must be S256 (RFC 7636 section 4.3).', true);
        }
        try {
            return new CodeChallenge($challenge, CodeChallengeMethod::S256);
        } catch (InvalidArgumentException) {
            throw new InvalidRequestException('The code_challenge parameter is not 43 to 128 unreserved characters (RFC 7636 section 4.2).', true);
        }
    }

    /**
     * OIDC Core §3.1.2.1 "prompt": a closed list, "none" alone.
     *
     * @return list<Prompt>
     */
    private static function prompts(?string $prompt): array
    {
        if ($prompt === null) {
            return [];
        }
        $prompts = [];
        foreach (explode(' ', $prompt) as $value) {
            $candidate = Prompt::tryFrom($value);
            if ($candidate === null) {
                throw new InvalidRequestException('The prompt parameter is not a space-separated list of none, login, consent or select_account.', true);
            }
            if (! in_array($candidate, $prompts, true)) {
                $prompts[] = $candidate;
            }
        }
        if (in_array(Prompt::None, $prompts, true) && count($prompts) > 1) {
            throw new InvalidRequestException('The prompt value none cannot be combined with another value (OIDC Core section 3.1.2.1).', true);
        }

        return $prompts;
    }

    private static function display(?string $display): ?Display
    {
        if ($display === null) {
            return null;
        }

        return Display::tryFrom($display) ?? throw new InvalidRequestException('The display parameter is not one of page, popup, touch or wap.', true);
    }

    private static function claims(?string $claims): ?ClaimsRequest
    {
        if ($claims === null) {
            return null;
        }
        try {
            return ClaimsRequest::fromJson($claims);
        } catch (InvalidArgumentException) {
            throw new InvalidRequestException('The claims parameter is not a claims request (OIDC Core section 5.5).', true);
        }
    }
}

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Authorization;

use function count;
use function explode;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Scope\Scopes;
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
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\KeyConfirmation;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\InvalidScopeException;
use Heidi\Oidc\Exception\InvalidTargetException;
use Heidi\Oidc\Exception\LogicException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Exception\UnsupportedResponseModeException;
use Heidi\Oidc\Exception\UnsupportedResponseTypeException;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use Heidi\Oidc\Port\ServedResponseModesInterface;
use function in_array;
use function is_string;
use function preg_match;
use function sprintf;

/**
 * Reads an authorization request (RFC 6749 §4.1.1, OIDC Core §3.1.2.1) in the two stages of RFC 6749
 * §4.1.2.1: the client and the redirect URI first, whose failures are never redirected; everything else
 * then, whose failures go back to the client with "state" and "iss".
 *
 * It reads parameters and nothing else. A request the client pushed (RFC 9126 §4) and one it carried in
 * a JWT (RFC 9101 §6.1) are both resolved into parameters before they reach it, by the resolver of each,
 * so that the rules of a request are written once and judged once whichever way the request came in.
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
        private ServedResponseModesInterface $responseModes,
    ) {
    }

    /**
     * First stage (RFC 6749 §4.1.2.1, §3.1.2.3): the client, the redirect URI byte for byte, the state
     * and the mode the answer will use.
     *
     * @param array<string, mixed> $parameters
     * @param bool $pushed whether the parameters are the ones of a request the client pushed (RFC 9126
     *                     §2), which is the only way a client that requires it may start one
     * @param bool $signed whether they are the ones of a request object the client signed (RFC 9101
     *                     §6.1), directly or inside the record it pushed, which is the only way a client
     *                     that requires it may start one
     *
     * @throws OAuth2Exception never redirectable
     */
    public function redirectTarget(Tenant $tenant, array $parameters, bool $pushed = false, bool $signed = false): RedirectTarget
    {
        $request = RequestParameters::of($parameters);
        self::assertResolved($request);
        $client = $this->clients->findByClientId($tenant, $request->clientId());
        if ($client === null) {
            throw new InvalidRequestException('The client is unknown.');
        }
        // RFC 9126 §6: before the redirect URI is even read, so that a client held to pushing its
        // requests is told so on a page and nothing of the request reaches the browser it came from
        if (! $pushed && $client->registration->requiresPushedAuthorizationRequests) {
            throw new InvalidRequestException('The client only starts an authorization request by pushing it (RFC 9126 section 6).');
        }
        // OIDC Registration "require_signed_request_object", FAPI 2.0 Message Signing §5.3.1: read here
        // for the same reason, so that a client held to signing its requests is told so on a page and
        // nothing of the request reaches the browser it came from
        if (! $signed && $client->registration->requiresSignedRequestObject) {
            throw new InvalidRequestException('The client only starts an authorization request with a request object it signed (OIDC Registration, require_signed_request_object).');
        }
        $redirectUri = $request->required('redirect_uri');
        if (! $client->registration->hasRedirectUri($redirectUri)) {
            throw new InvalidRequestException('The redirect_uri parameter is not registered for this client.');
        }
        return new RedirectTarget($client, new RedirectUri($redirectUri), $request->state(), $this->responseMode($parameters));
    }

    /**
     * A request object is read before a request is parsed, by the resolver an endpoint calls first
     * (RFC 9101 §6.1): what the parser is given is the parameters of the object, never the object.
     * Finding one here is an endpoint wired without that resolver, which is a fault of the integration
     * and not of the request.
     */
    private static function assertResolved(RequestParameters $request): void
    {
        foreach (['request', 'request_uri'] as $name) {
            if ($request->isPresent($name)) {
                throw new LogicException(sprintf(
                    'The %s parameter reaches the parser, which means the endpoint was wired without the resolver that reads a request object (RFC 9101 section 6.1).',
                    $name,
                ));
            }
        }
    }

    /**
     * The mode the answer will use (OAuth 2.0 Multiple Response Type Encoding Practices §2.1), read with
     * the redirect URI because it says how anything reaches the client, a refusal of the second stage as
     * well as a code (OIDC Core §3.1.2.6). It refuses nothing, the failures of this stage being pages:
     * anything but a mode the integration wired falls back to the default, so that the refusal the
     * second stage throws reaches the client in the one mode it is sure to read. "jwt" is resolved
     * before anything is asked of it (JARM §2.1), so that what is kept is the mode that delivers.
     *
     * @param array<string, mixed> $parameters
     */
    private function responseMode(array $parameters): ResponseMode
    {
        $requested = $parameters['response_mode'] ?? null;
        if (! is_string($requested)) {
            return ResponseMode::Query;
        }
        $mode = self::requestedMode($requested);

        return $mode !== null && in_array($mode, $this->responseModes->servedResponseModes(), true) ? $mode : ResponseMode::Query;
    }

    /**
     * What a named mode delivers, or nothing when it names no mode of the specification.
     */
    private static function requestedMode(string $requested): ?ResponseMode
    {
        return ResponseMode::tryFrom($requested)?->resolved();
    }

    /**
     * Second stage (OIDC Core §3.1.2.2, RFC 7636 §4.4, architecture §4.2): everything else.
     *
     * @param array<string, mixed> $parameters
     *
     * @throws OAuth2Exception always redirectable
     */
    public function parse(RedirectTarget $target, array $parameters): AuthorizationRequest
    {
        $request = RequestParameters::of($parameters)->withRedirectableFailures();
        $responseType = $request->required('response_type');
        if ($responseType !== 'code') {
            throw new UnsupportedResponseTypeException('Only the code response type is supported.');
        }

        $responseMode = $request->optional('response_mode');
        if ($responseMode !== null && self::requestedMode($responseMode) !== $target->responseMode) {
            throw new UnsupportedResponseModeException('The requested response mode is not supported.');
        }

        $scopes = $this->scopes($target, $request->required('scope'));
        $codeChallenge = self::codeChallenge(
            $target->client,
            $request->optional('code_challenge'),
            $request->optional('code_challenge_method'),
        );

        $nonce = $request->text('nonce');
        $prompts = self::prompts($request->optional('prompt'));
        $maxAge = $request->optional('max_age');
        if ($maxAge !== null && preg_match(self::MAX_AGE_PATTERN, $maxAge) !== 1) {
            throw new InvalidRequestException('The max_age parameter must be a non-negative integer.', true);
        }
        $loginHint = $request->text('login_hint');
        $uiLocales = $request->uiLocales();
        $acrValues = $request->list(
            'acr_values',
            self::ACR_VALUE_PATTERN,
            'The acr_values parameter must be a space-separated list of printable ASCII values.',
        );
        $display = self::display($request->optional('display'));
        $idTokenHint = $request->compactJws('id_token_hint');
        $claims = self::claims($request->optional('claims'));
        $dpopKey = self::dpopKey($request->optional('dpop_jkt'));
        $resources = self::resources($target->client, $request->repeated('resource'));

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
            $target->responseMode,
            $dpopKey,
            $resources,
        );
    }

    /**
     * RFC 8707 §2.1: the resources the tokens of this request will be addressed to, named once each or
     * several times over. What a client may ask for is what it registered, as every other list of a
     * client is: a resource outside it is "invalid_target", and so is a value that is not an absolute
     * URI. A request that names none asks for none, and its tokens are addressed to the client itself.
     *
     * @param list<string> $values
     *
     * @throws InvalidTargetException when a value is not an absolute URI, or names a resource the
     *                                client is not registered for
     */
    private static function resources(Client $client, array $values): ?ResourceIndicators
    {
        if ($values === []) {
            return null;
        }
        try {
            $resources = ResourceIndicators::of($values);
        } catch (InvalidArgumentException $exception) {
            throw InvalidTargetException::notAnAbsoluteUri(true, $exception);
        }
        if (! $client->registration->allowsResources($resources)) {
            throw InvalidTargetException::notRegistered(true);
        }

        return $resources;
    }

    /**
     * RFC 9449 §10: the key the client will exchange the code with, named by its JWK thumbprint, so that
     * a code stolen on its way back is worth nothing to whoever does not hold that key. A request that
     * names one is a request whose token exchange must prove it, whether the client pushed the request
     * or signed it.
     */
    private static function dpopKey(?string $thumbprint): ?KeyConfirmation
    {
        if ($thumbprint === null) {
            return null;
        }
        try {
            return new KeyConfirmation($thumbprint);
        } catch (InvalidArgumentException $exception) {
            throw new InvalidRequestException(
                'The dpop_jkt parameter is the JWK thumbprint of a key, the base64url of a SHA-256 (RFC 9449 section 10).',
                true,
                $exception,
            );
        }
    }

    /**
     * RFC 6749 §3.3, OIDC Core §3.1.2.2 step 3: contains "openid", every token allowed to the client.
     *
     * @throws InvalidScopeException when it is not a list of scope tokens, when it names a scope the
     *                               client is not allowed, or when it does not name "openid"
     */
    private function scopes(RedirectTarget $target, string $scope): Scopes
    {
        try {
            $scopes = Scopes::parse($scope);
        } catch (InvalidArgumentException $exception) {
            throw InvalidScopeException::notASpaceSeparatedList(true, $exception);
        }
        foreach ($scopes->all as $candidate) {
            if (! $target->client->registration->allowedScopes->has($candidate)) {
                throw new InvalidScopeException('The requested scope is not allowed for this client.', true);
            }
        }
        if (! $scopes->has(Scope::openid())) {
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
        if ($challenge === null && $method === null && ! $client->registration->requiresPkce) {
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

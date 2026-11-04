<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\Authorization\AuthorizationRequest;
use Beffroi\Oidc\Domain\Authorization\RedirectTarget;
use Beffroi\Oidc\Domain\Authorization\ResponseTypeNames;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Exception\UnsupportedResponseTypeException;
use Beffroi\Oidc\Port\AuthorizationDetailsReaderInterface;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use Beffroi\Oidc\Port\CodeChallengeMethodsInterface;
use Beffroi\Oidc\Port\ServedResponseModesInterface;
use function sprintf;

/**
 * RFC 6749 §4.1.1, OIDC Core §3.1.2.1
 */
final readonly class AuthorizationRequestParser
{
    private RequestedResponseMode $responseMode;

    private RequestedAuthorizationDetails $authorizationDetails;

    private RequestedCodeChallenge $codeChallenge;

    public function __construct(
        private ClientRepositoryInterface $clients,
        ServedResponseModesInterface $responseModes,
        AuthorizationDetailsReaderInterface $authorizationDetailTypes,
        CodeChallengeMethodsInterface $codeChallengeMethods,
    ) {
        $this->responseMode = new RequestedResponseMode($responseModes);
        $this->authorizationDetails = new RequestedAuthorizationDetails($authorizationDetailTypes);
        $this->codeChallenge = new RequestedCodeChallenge($codeChallengeMethods);
    }

    /**
     * RFC 6749 §4.1.2.1, §3.1.2.3
     *
     * @param array<string, mixed> $parameters
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
        // RFC 9126 §6: before the redirect URI is read, so the refusal is a page and nothing is redirected.
        if (! $pushed && $client->registration->requiresPushedAuthorizationRequests) {
            throw new InvalidRequestException('The client only starts an authorization request by pushing it (RFC 9126 section 6).');
        }
        // RFC 9101 §10.5: before the redirect URI too, for the same reason.
        if (! $signed && $client->registration->requiresSignedRequestObject) {
            throw new InvalidRequestException('The client only starts an authorization request with a request object it signed (RFC 9101 section 10.5, require_signed_request_object).');
        }
        $redirectUri = $request->required('redirect_uri');
        if (! $client->registration->hasRedirectUri($redirectUri)) {
            throw new InvalidRequestException('The redirect_uri parameter is not registered for this client.');
        }
        return new RedirectTarget($client, new RedirectUri($redirectUri), $request->state(), $this->responseMode->of($parameters));
    }

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
     * OIDC Core §3.1.2.2, RFC 7636 §4.4
     *
     * @param array<string, mixed> $parameters
     *
     * @throws OAuth2Exception always redirectable
     */
    public function parse(RedirectTarget $target, array $parameters): AuthorizationRequest
    {
        $request = RequestParameters::of($parameters)->withRedirectableFailures();
        if ($request->required('response_type') !== ResponseTypeNames::CODE) {
            throw new UnsupportedResponseTypeException('Only the code response type is supported.');
        }
        $this->responseMode->assertItIsTheOneDelivered($request, $target->responseMode);

        $interaction = RequestedInteraction::of($request);

        return new AuthorizationRequest(
            $target->client,
            $target->redirectUri,
            RequestedScopes::of($target->client, $request->required('scope')),
            $this->codeChallenge->of(
                $target->client,
                $request->optional('code_challenge'),
                $request->optional('code_challenge_method'),
            ),
            $target->state,
            $request->text('nonce'),
            $interaction->prompts,
            $interaction->maxAge,
            $interaction->loginHint,
            $interaction->uiLocales,
            $interaction->acrValues,
            $interaction->display,
            $interaction->idTokenHint,
            $interaction->claims,
            $target->responseMode,
            RequestedCodeReservation::of($request->optional('dpop_jkt')),
            RequestedResources::of($target->client, $request->repeated('resource')),
            $this->authorizationDetails->of($target->client, $request->optional('authorization_details')),
        );
    }
}

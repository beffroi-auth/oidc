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
 * Reads an authorization request (RFC 6749 §4.1.1, OIDC Core §3.1.2.1) in the two stages of RFC 6749
 * §4.1.2.1: the client and the redirect URI first, whose failures are never redirected; everything else
 * then, whose failures go back to the client with "state" and "iss".
 *
 * The two stages are two methods of one class because they are the two halves of one rule, when a failure
 * may be redirected at all (RFC 9700 §4.1); what each parameter of the second stage must be is not here
 * but in a class per group of them that belong together (`Requested*`), so that what is left is the stage
 * and not the dozen readings.
 *
 * It reads parameters and nothing else. A request the client pushed (RFC 9126 §4) and one it carried in
 * a JWT (RFC 9101 §6.1) are both resolved into parameters before they reach it, by the resolver of each,
 * so that the rules of a request are written once and judged once whichever way the request came in.
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
        return new RedirectTarget($client, new RedirectUri($redirectUri), $request->state(), $this->responseMode->of($parameters));
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
     * Second stage (OIDC Core §3.1.2.2, RFC 7636 §4.4, architecture §4.2): everything else, each
     * parameter judged by the class that owns its rule.
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

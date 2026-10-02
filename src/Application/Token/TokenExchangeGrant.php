<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use DateTimeImmutable;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Application\Client\AuthenticatedClient;
use Beffroi\Oidc\Application\Exchange\PresentedTokenTypes;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Client\TokenExchange;
use Beffroi\Oidc\Domain\Exchange\Actor;
use Beffroi\Oidc\Domain\Exchange\PresentedToken;
use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\ClientSubject;
use Beffroi\Oidc\Domain\Token\IssuedTokens;
use Beffroi\Oidc\Domain\Token\SubjectAuthorization;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\InvalidScopeException;
use Beffroi\Oidc\Exception\InvalidTargetException;
use Beffroi\Oidc\Exception\UnauthorizedClientException;
use Psr\Clock\ClockInterface;
use function sprintf;

/**
 * RFC 8693 §2.1 (architecture §4.5): the grant of a service that acts for somebody else. It takes a token
 * this provider issued and gives back another one, about the same subject, addressed to another resource,
 * good for no more than the first.
 *
 * The two cases of §1.3 are told apart by the request and by nothing else: an "actor_token" makes it a
 * delegation, and the token that comes out carries an "act" naming who acts (§4.1); no "actor_token" makes it
 * an impersonation, and the token that comes out says nothing of anybody acting. There is no flag, no scope
 * and no registration option that turns one into the other.
 *
 * What a client may ask is registered and never asked for (TokenExchange): which types of token it may
 * present, which resources it may ask the new token for, and whether it may act for a user at all. A client
 * with no such registration is refused whatever it presents.
 *
 * Nothing widens. The scopes of the new token are a subset of the ones the presented token carried, the
 * resources are a subset of the ones it was addressed to, and a token addressed to its own client is not
 * exchangeable at all: there would be nothing to narrow, and the new token could only be addressed outside
 * what the old one covered. The new token descends from the grant the old one descended from, so taking that
 * grant back takes both, and a session that ended refuses both.
 *
 * "may_act" is the subject's word on the matter (§4.4): when the token says who may act for its subject,
 * whoever asks is compared with it and refused when it is somebody else, the registration of the asking
 * client notwithstanding.
 */
final readonly class TokenExchangeGrant implements ExchangesATokenInterface
{
    public const string GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';

    public function __construct(
        private PresentedTokenTypes $types,
        private TokenIssuer $issuer,
        private ClockInterface $clock,
    ) {
    }

    public function grantType(): GrantTypeName
    {
        return new GrantTypeName(self::GRANT_TYPE);
    }

    public function grant(AuthenticatedClient $client, RequestParameters $request, RequestContext $context): IssuedTokens
    {
        $now = $this->clock->now();
        $registered =
            $client->client->registration->tokenExchange ?? throw new UnauthorizedClientException('The client is not registered for a token exchange (RFC 8693 section 2.1).');
        self::assertIssuesWhatIsAskedFor($request);
        $subjectToken = $this->present($client, $request, $registered, 'subject_token', $now);
        if ($subjectToken->isAboutAUser() && ! $registered->mayActForAUser) {
            throw new InvalidRequestException('The client is not registered to act for a user, and the token it presented is about one (RFC 8693 section 2.1).');
        }
        $actor = $this->actorOf($client, $request, $registered, $subjectToken, $now);
        self::assertTheSubjectAllows($client, $subjectToken, $actor);

        $granted = self::grantedResources($subjectToken);
        $authorization = new SubjectAuthorization(
            $this->grantType(),
            $subjectToken->grantId,
            $client->client,
            $subjectToken->subject,
            self::scopes($request, $subjectToken),
            $subjectToken->scopes,
            RequestedResources::of($request, $granted) ?? $granted,
            $granted,
            $subjectToken->signIn,
            $actor,
            $client->confirmation,
        );

        return $this->issuer->issue($authorization, null, $context, $now)->withIssuedTokenType(TokenTypeIdentifier::accessToken());
    }

    /**
     * RFC 8693 §2.1: the token the request presents under that name, read by the type it names, which is one
     * the provider is wired to read and one the client registered for. The type is required beside the token
     * (§2.1), and nothing is read of a value whose type the request did not name.
     *
     * @param non-empty-string $name "subject_token" or "actor_token"
     *
     * @throws InvalidArgumentException when the wiring does not hold together
     * @throws InvalidRequestException when the type is missing, unwired, unregistered, or the token is not one this provider honours
     */
    private function present(
        AuthenticatedClient $client,
        RequestParameters $request,
        TokenExchange $registered,
        string $name,
        DateTimeImmutable $now,
    ): PresentedToken {
        $named = $request->required($name . '_type');
        $type = $this->types->named($named);
        if ($type === null) {
            throw new InvalidRequestException(sprintf('The %s_type is not a type of token this provider reads (RFC 8693 section 3).', $name));
        }
        if (! $registered->allowsTokenType($type->identifier())) {
            throw new InvalidRequestException(sprintf('The %s_type is not a type of token this client may present (RFC 8693 section 2.1).', $name));
        }

        return $type->read($client->client->tenant, $request->required($name), $now);
    }

    /**
     * RFC 8693 §1.3, §4.1: who acts for the subject, null when nobody does. An "actor_token" makes the
     * exchange a delegation and its subject the actor, added around whatever the presented token already
     * recorded so that a chain of two exchanges nests and does not flatten.
     *
     * The actor token names the client that presents it and no other: a token is held by whoever holds it, so
     * one naming somebody else would let a client write that somebody else into the "act" of a token nobody
     * else asked for. A type beside the token is required when the token is there and refused when it is not
     * (§2.1).
     *
     * @throws InvalidArgumentException when the wiring does not hold together
     * @throws InvalidRequestException
     */
    private function actorOf(
        AuthenticatedClient $client,
        RequestParameters $request,
        TokenExchange $registered,
        PresentedToken $subjectToken,
        DateTimeImmutable $now,
    ): ?Actor {
        if (! $request->isPresent('actor_token')) {
            if ($request->isPresent('actor_token_type')) {
                throw new InvalidRequestException('The actor_token_type names the type of an actor_token, and the request carries none (RFC 8693 section 2.1).');
            }

            return $subjectToken->actor;
        }
        $actorToken = $this->present($client, $request, $registered, 'actor_token', $now);
        if ($actorToken->client->registration->clientId !== $client->client->registration->clientId) {
            throw new InvalidRequestException('The actor token names the client that presents it (RFC 8693 section 2.1).');
        }

        return new Actor($actorToken->subject, $subjectToken->actor);
    }

    /**
     * RFC 8693 §2.1: what this provider issues is an access token, so a request that asks for another type
     * asks for something it cannot answer. Absent, the request asks for the one thing there is.
     *
     * The "audience" parameter is refused: what a token of this provider is addressed to is named by the
     * resource indicators of RFC 8707 §2, in one place (TokenAudience, issue #217), and a logical name beside
     * them would be a second way of saying the same thing with no registration behind it.
     *
     * @throws InvalidRequestException
     * @throws InvalidTargetException
     */
    private static function assertIssuesWhatIsAskedFor(RequestParameters $request): void
    {
        $requested = $request->optional('requested_token_type');
        if ($requested !== null && $requested !== TokenTypeIdentifier::ACCESS_TOKEN) {
            throw new InvalidRequestException(sprintf(
                'This provider issues tokens of type %s, and the request asks for another one (RFC 8693 section 2.1).',
                TokenTypeIdentifier::ACCESS_TOKEN,
            ));
        }
        if ($request->isPresent('audience')) {
            throw new InvalidTargetException('What a token of this provider is addressed to is named by the resource parameter (RFC 8707 section 2), and not by an audience (RFC 8693 section 2.1).');
        }
    }

    /**
     * RFC 8693 §4.4: the subject's own word on who may act for them. A token that carries none says nothing,
     * and the registration of the client that asks is what decides; a token that carries one narrows that to
     * a single party. Whoever is about to hold the new token is the party compared: the actor of a delegation
     * and, when nobody acts, the client itself, impersonation being acting in the strongest sense.
     *
     * @throws InvalidRequestException
     */
    private static function assertTheSubjectAllows(AuthenticatedClient $client, PresentedToken $subjectToken, ?Actor $actor): void
    {
        $mayAct = $subjectToken->mayAct;
        if ($mayAct === null) {
            return;
        }
        if (! $mayAct->allows($actor ?? new Actor(ClientSubject::of($client->client)))) {
            throw new InvalidRequestException('The presented token names somebody else as the party that may act for its subject (RFC 8693 section 4.4).');
        }
    }

    /**
     * RFC 8693 §2.1: the scopes of the new token are a subset of the ones the presented token carried. A
     * request that names none narrows nothing and is served what it already held, which grants it nothing it
     * did not have; a request that names more is refused rather than served less than it asked for.
     *
     * @throws InvalidScopeException
     */
    private static function scopes(RequestParameters $request, PresentedToken $subjectToken): Scopes
    {
        $scope = $request->optional('scope');
        if ($scope === null) {
            return $subjectToken->scopes;
        }
        try {
            $scopes = Scopes::parse($scope);
        } catch (InvalidArgumentException $exception) {
            throw InvalidScopeException::notASpaceSeparatedList(previous: $exception);
        }
        if (! $subjectToken->scopes->covers($scopes)) {
            throw new InvalidScopeException('The requested scope is not among the ones the presented token carries (RFC 8693 section 2.1).');
        }

        return $scopes;
    }

    /**
     * RFC 8693 §2.1, RFC 8707 §2: the resources the new token may be addressed to are the ones the presented
     * token was addressed to. A token addressed to its own client was asked for no resource at all, so there
     * is nothing to narrow and the exchange is refused rather than answered with a token addressed somewhere
     * the old one never reached.
     *
     * @throws InvalidTargetException
     */
    private static function grantedResources(PresentedToken $subjectToken): ResourceIndicators
    {
        try {
            return ResourceIndicators::of($subjectToken->audience->values);
        } catch (InvalidArgumentException $exception) {
            throw new InvalidTargetException(
                'The presented token is addressed to the client that holds it and to no resource, and an exchange narrows what it is addressed to (RFC 8693 section 2.1).',
                previous: $exception,
            );
        }
    }
}

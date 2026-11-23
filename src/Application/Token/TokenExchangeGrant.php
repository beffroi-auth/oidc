<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use DateTimeImmutable;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Oidc\Application\Client\AuthenticatedClient;
use Beffroi\Oidc\Application\Exchange\PresentedTokenTypes;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
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
 * RFC 8693 §2.1
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
        self::assertTheSubjectAllows($client, $subjectToken);

        $registration = $client->client->registration;
        $granted = self::grantedResources($subjectToken);
        $authorization = new SubjectAuthorization(
            $this->grantType(),
            $subjectToken->grantId,
            $client->client,
            $subjectToken->subject,
            self::scopes($request, $subjectToken, $registration),
            $subjectToken->scopes,
            self::resources($request, $granted, $registration),
            $granted,
            $subjectToken->signIn,
            $actor,
            $client->confirmation,
            $subjectToken->person,
        );

        return $this->issuer->issue($authorization, null, $context, $now)->withIssuedTokenType(TokenTypeIdentifier::accessToken());
    }

    /**
     * RFC 8693 §2.1
     *
     * @param non-empty-string $name "subject_token" or "actor_token"
     *
     * @throws InvalidArgumentException when the wiring does not hold together
     * @throws InvalidRequestException
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
     * RFC 8693 §1.3, §4.1
     *
     * The actor token is one the client holds for itself, or a client could write somebody else, a person included,
     * into the "act".
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
        if (! $actorToken->isHeldForItselfBy($client->client)) {
            throw new InvalidRequestException('The actor token is one the client that presents it holds for itself, and names no person (RFC 8693 section 2.1).');
        }

        return new Actor($actorToken->subject, $subjectToken->actor);
    }

    /**
     * RFC 8693 §2.1
     *
     * "audience" is refused: a token of this provider is addressed by its resource indicators (RFC 8707 §2) alone.
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
     * RFC 8693 §4.4
     *
     * The client that will hold the new token is compared, never an actor the presented token names: it is the actor
     * of a delegation, and an impersonation is acting in the strongest sense.
     *
     * @throws InvalidRequestException
     */
    private static function assertTheSubjectAllows(AuthenticatedClient $client, PresentedToken $subjectToken): void
    {
        $mayAct = $subjectToken->mayAct;
        if ($mayAct === null) {
            return;
        }
        if (! $mayAct->allows(new Actor(ClientSubject::of($client->client)))) {
            throw new InvalidRequestException('The presented token names somebody else as the party that may act for its subject (RFC 8693 section 4.4).');
        }
    }

    /**
     * RFC 8693 §2.1, RFC 6749 §3.3
     *
     * @throws InvalidScopeException
     */
    private static function scopes(RequestParameters $request, PresentedToken $subjectToken, ClientRegistration $registration): Scopes
    {
        $scopes = $subjectToken->scopes;
        $scope = $request->optional('scope');
        if ($scope !== null) {
            try {
                $scopes = Scopes::parse($scope);
            } catch (InvalidArgumentException $exception) {
                throw InvalidScopeException::notASpaceSeparatedList(previous: $exception);
            }
            if (! $subjectToken->scopes->covers($scopes)) {
                throw new InvalidScopeException('The requested scope is not among the ones the presented token carries (RFC 8693 section 2.1).');
            }
        }
        if (! $registration->allowedScopes->covers($scopes)) {
            throw InvalidScopeException::notRegistered();
        }

        return $scopes;
    }

    /**
     * RFC 8707 §2, RFC 8693 §2.1
     *
     * @throws InvalidTargetException
     */
    private static function resources(RequestParameters $request, ResourceIndicators $granted, ClientRegistration $registration): ResourceIndicators
    {
        $resources = RequestedResources::of($request, $granted) ?? $granted;
        if (! $registration->allowsResources($resources)) {
            throw InvalidTargetException::notRegistered();
        }

        return $resources;
    }

    /**
     * RFC 8693 §2.1, RFC 8707 §2
     *
     * A token addressed to its own client is refused: the new one could only reach where the old one never did. It is
     * refused before its audience is read as resources, which a client identifier in the form of a URI would pass for.
     *
     * @throws InvalidTargetException
     */
    private static function grantedResources(PresentedToken $subjectToken): ResourceIndicators
    {
        if ($subjectToken->audience->has($subjectToken->client->registration->clientId)) {
            throw new InvalidTargetException('The presented token is addressed to the client that holds it and to no resource, and an exchange narrows what it is addressed to (RFC 8693 section 2.1).');
        }
        try {
            return ResourceIndicators::of($subjectToken->audience->values);
        } catch (InvalidArgumentException $exception) {
            throw new InvalidTargetException(
                'The presented token is addressed to something that is not a resource, and an exchange narrows what it is addressed to (RFC 8707 section 2).',
                previous: $exception,
            );
        }
    }
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Exchange\Actor;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;
use function sprintf;

/**
 * What a client is entitled to for a subject it did not sign in (architecture §4.5): an authorization whose
 * subject was named by what the client presented, a token this provider issued (RFC 8693 §2.1) or an
 * assertion of an issuer the tenant trusts (RFC 7523 §2.1).
 *
 * There is no session of this provider behind the request, so nothing of one is invented: what the token it
 * descends from said of a sign-in is carried unchanged and what said nothing carries nothing. There is
 * nobody to ask either, so there is no consent, no nonce and no ID token; a client that wants one signs a
 * user in.
 *
 * What it stands on is what the client presented, narrowed by the registration of the client that asks: the
 * scopes and the resources are a subset of the ones the presented token or the trusted issuer carried, never
 * a superset (RFC 8693 §2.1), and the resources are named by the request, because a token addressed to the
 * client that asked for it is a token no resource server is meant to accept.
 */
final readonly class SubjectAuthorization implements NamesItsSubjectInterface
{
    public Tenant $tenant;

    /**
     * @param GrantTypeName $grantType the grant that produced this authorization, as it names itself
     * @param Uuid $grantId what the tokens of this response descend from: the grant of the token that was presented, so that taking that one back takes these with it
     * @param Client $client the client that asked, which the tokens name in "client_id" (RFC 9068 §2.2)
     * @param Subject $subject the "sub" of the tokens of this response, as whatever named it named it
     * @param Scopes $scopes what this response carries, among the granted ones
     * @param Scopes $grantedScopes what the presented token or the trusted issuer carried
     * @param ResourceIndicators $resources what the access token is addressed to (RFC 8707 §2), at least one
     * @param ResourceIndicators $grantedResources what it may be addressed to, as what was presented allows
     * @param TokenSignIn|null $signIn the sign-in the presented token descended from, null when it descended from none
     * @param Actor|null $actor who acts for the subject (RFC 8693 §4.1), null for an impersonation and for a grant where nobody acts
     * @param ConfirmationInterface|null $confirmation what the access token of this response is bound to (RFC 8705 §3, RFC 9449 §6.1), null when it is a bearer token
     * @param Subject|null $person the person the acts of this authorization are in the name of (issue #588), null when nothing read the subject back as one
     *
     * @throws InvalidArgumentException when the client could not have been granted this
     */
    public function __construct(
        public GrantTypeName $grantType,
        public Uuid $grantId,
        public Client $client,
        public Subject $subject,
        public Scopes $scopes,
        public Scopes $grantedScopes,
        public ResourceIndicators $resources,
        public ResourceIndicators $grantedResources,
        public ?TokenSignIn $signIn = null,
        public ?Actor $actor = null,
        public ?ConfirmationInterface $confirmation = null,
        public ?Subject $person = null,
    ) {
        $registration = $client->registration;
        if ($registration->isPublic()) {
            throw new InvalidArgumentException('An authorization for a subject nobody signed in here is granted to a client that authenticates itself (RFC 8693 section 2.1, RFC 7523 section 2.1).');
        }
        if (! $grantedScopes->covers($scopes)) {
            throw new InvalidArgumentException(sprintf(
                'The scopes of a response are among the granted ones (RFC 8693 section 2.1): %s.',
                (string) $grantedScopes,
            ));
        }
        if (! $registration->allowedScopes->covers($scopes)) {
            throw new InvalidArgumentException('The scopes of a response are among the ones the client registered (RFC 6749 section 3.3).');
        }
        if (! $grantedResources->covers($resources)) {
            throw new InvalidArgumentException('The resources of a response are among the granted ones (RFC 8693 section 2.1).');
        }
        if (! $registration->allowsResources($resources)) {
            throw new InvalidArgumentException('The resources of a response are among the ones the client registered (RFC 8707 section 2.1).');
        }
        $this->tenant = $client->tenant;
    }

    public function audience(): TokenAudience
    {
        return TokenAudience::of($this->client, $this->resources);
    }

    public function person(): ?Subject
    {
        return $this->person;
    }

    public function storedUnder(string $tokenHash, DateTimeImmutable $now, DateTimeImmutable $expiresAt): StoredSubjectAccessToken
    {
        return StoredSubjectAccessToken::fromAuthorization($tokenHash, $this, $now, $expiresAt);
    }
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * What a client acting for itself is entitled to (RFC 6749 §4.4, architecture §4.5): an authorization with
 * nobody behind it. There is no session, so there is no "sid" and no "sub" of a user; there is no
 * authentication, so there is nothing to say of an "acr", an "amr" or an "auth_time"; and there is nobody
 * to ask, so there is no consent and no ID token.
 *
 * What it stands on is the registration of the client itself: the scopes it was registered for are the
 * scopes it is granted, and the resources it was registered for are the resources it may be addressed to
 * (RFC 8707 §2.1). The response narrows both, and the access token is addressed to a resource the request
 * named, never to the client itself: a token whose audience is the client that asked for it is a token no
 * resource server is meant to accept, and this grant exists to reach one.
 */
final readonly class ClientAuthorization implements AuthorizationInterface
{
    public Tenant $tenant;

    public Scopes $scopes;

    public Scopes $grantedScopes;

    public ResourceIndicators $resources;

    public ResourceIndicators $grantedResources;

    /**
     * @param Scopes $scopes what this response carries, among the ones the client registered
     * @param ResourceIndicators $resources what the access token is addressed to, among the ones the client registered (RFC 8707 §2)
     * @param ConfirmationInterface|null $confirmation what the access token of this response is bound to (RFC 8705 §3, RFC 9449 §6.1), null when it is a bearer token
     *
     * @throws InvalidArgumentException when the client could not have been granted this
     */
    public function __construct(
        public GrantTypeName $grantType,
        public Uuid $grantId,
        public Client $client,
        Scopes $scopes,
        ResourceIndicators $resources,
        public ?ConfirmationInterface $confirmation = null,
    ) {
        $registration = $client->registration;
        if ($registration->isPublic()) {
            throw new InvalidArgumentException('An authorization with nobody behind it is granted to a client that authenticates itself (RFC 6749 section 4.4).');
        }
        if (! $registration->allowedScopes->covers($scopes)) {
            throw new InvalidArgumentException('The scopes of a response are among the ones the client registered (RFC 6749 section 3.3).');
        }
        if (! $registration->allowsResources($resources)) {
            throw new InvalidArgumentException('The resources of a response are among the ones the client registered (RFC 8707 section 2.1).');
        }
        $this->tenant = $client->tenant;
        $this->grantedScopes = $registration->allowedScopes;
        $this->resources = $resources;
        $this->grantedResources = new ResourceIndicators($registration->resources);
        $this->scopes = $scopes;
    }

    public function audience(): TokenAudience
    {
        return TokenAudience::of($this->client, $this->resources);
    }

    /**
     * RFC 6749 §4.4: nobody is behind it, so the acts it produces are in nobody's name.
     */
    public function person(): ?Subject
    {
        return null;
    }

    public function storedUnder(string $tokenHash, DateTimeImmutable $now, DateTimeImmutable $expiresAt): StoredClientAccessToken
    {
        return StoredClientAccessToken::fromAuthorization($tokenHash, $this, $now, $expiresAt);
    }
}

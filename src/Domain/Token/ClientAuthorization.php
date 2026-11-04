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
 * RFC 6749 §4.4
 */
final readonly class ClientAuthorization implements AuthorizationInterface
{
    public Tenant $tenant;

    public Scopes $scopes;

    public Scopes $grantedScopes;

    public ResourceIndicators $resources;

    public ResourceIndicators $grantedResources;

    /**
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

    public function person(): ?Subject
    {
        return null;
    }

    public function storedUnder(string $tokenHash, DateTimeImmutable $now, DateTimeImmutable $expiresAt): StoredClientAccessToken
    {
        return StoredClientAccessToken::fromAuthorization($tokenHash, $this, $now, $expiresAt);
    }
}

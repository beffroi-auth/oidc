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
 * RFC 8693 §2.1, RFC 7523 §2.1
 */
final readonly class SubjectAuthorization implements NamesItsSubjectInterface
{
    public Tenant $tenant;

    /**
     * @param Uuid $grantId the presented token's grant, so that taking that one back takes these with it
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

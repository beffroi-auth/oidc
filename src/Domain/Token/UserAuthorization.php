<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Authorization\AuthorizationCode;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

final readonly class UserAuthorization implements UserAuthorizationInterface
{
    public Tenant $tenant;

    public User $user;

    public Scopes $scopes;

    public Scopes $grantedScopes;

    public ?ResourceIndicators $resources;

    public ?ResourceIndicators $grantedResources;

    public ?AuthorizationDetails $authorizationDetails;

    public ?AuthorizationDetails $grantedAuthorizationDetails;

    public function __construct(
        public GrantTypeName $grantType,
        public Uuid $grantId,
        public Client $client,
        public AuthenticationSession $session,
        Scopes $scopes,
        Scopes $grantedScopes,
        public ?string $nonce,
        public ?ClaimsRequest $claimsRequest,
        public AuthenticationSnapshot $authentication,
        public ?ConfirmationInterface $confirmation = null,
        ?ResourceIndicators $resources = null,
        ?ResourceIndicators $grantedResources = null,
        ?AuthorizationDetails $authorizationDetails = null,
        ?AuthorizationDetails $grantedAuthorizationDetails = null,
    ) {
        if (! $session->tenant->equals($client->tenant)) {
            throw new InvalidArgumentException('An authorization binds a session and a client of the same tenant.');
        }
        if (! $grantedScopes->covers($scopes)) {
            throw new InvalidArgumentException('The scopes of a response are among the granted ones (RFC 6749 section 6).');
        }
        if ($resources !== null && ($grantedResources === null || ! $grantedResources->covers($resources))) {
            throw new InvalidArgumentException('The resources of a response are among the granted ones (RFC 8707 section 2.2).');
        }
        if ($authorizationDetails !== null && ($grantedAuthorizationDetails === null || ! $grantedAuthorizationDetails->covers($authorizationDetails))) {
            throw new InvalidArgumentException('The authorization details of a response are among the granted ones (RFC 9396 section 7).');
        }
        $this->tenant = $client->tenant;
        $this->user = $session->user;
        $this->scopes = $scopes;
        $this->grantedScopes = $grantedScopes;
        $this->resources = $resources;
        $this->grantedResources = $grantedResources;
        $this->authorizationDetails = $authorizationDetails;
        $this->grantedAuthorizationDetails = $grantedAuthorizationDetails;
    }

    public function audience(): TokenAudience
    {
        return TokenAudience::of($this->client, $this->resources);
    }

    public function person(): Subject
    {
        return $this->user->subject;
    }

    public function storedUnder(string $tokenHash, DateTimeImmutable $now, DateTimeImmutable $expiresAt): StoredUserAccessToken
    {
        return StoredUserAccessToken::fromAuthorization($tokenHash, $this, $now, $expiresAt);
    }

    /**
     * RFC 6749 §4.1.3, OIDC Core §3.1.3
     */
    public static function fromAuthorizationCode(
        GrantTypeName $grantType,
        AuthorizationCode $code,
        ?ConfirmationInterface $confirmation = null,
        ?ResourceIndicators $resources = null,
        ?AuthorizationDetails $authorizationDetails = null,
    ): self {
        return new self(
            $grantType,
            $code->grantId,
            $code->client,
            $code->session,
            $code->scopes,
            $code->scopes,
            $code->nonce,
            $code->claimsRequest,
            $code->authentication,
            $confirmation,
            $resources ?? $code->resources,
            $code->resources,
            $authorizationDetails ?? $code->authorizationDetails,
            $code->authorizationDetails,
        );
    }

    /**
     * RFC 6749 §6, OIDC Core §12.2
     *
     * The tokens are bound to what the client proved at this request, not at the grant (RFC 8705 §3).
     */
    public static function fromRefreshToken(
        GrantTypeName $grantType,
        RefreshToken $token,
        ?Scopes $scopes,
        ?ConfirmationInterface $confirmation = null,
        ?ResourceIndicators $resources = null,
        ?AuthorizationDetails $authorizationDetails = null,
    ): self {
        return new self(
            $grantType,
            $token->family->grantId,
            $token->client,
            $token->session,
            $scopes ?? $token->scopes,
            $token->scopes,
            null,
            $token->claimsRequest,
            $token->authentication,
            $confirmation,
            $resources ?? $token->resources,
            $token->resources,
            $authorizationDetails ?? $token->authorizationDetails,
            $token->authorizationDetails,
        );
    }
}

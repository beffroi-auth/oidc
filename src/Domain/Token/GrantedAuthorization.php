<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\GrantTypeName;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * What a verified grant entitles the client to (architecture §4.5), read by the token issuers. "scopes"
 * is what this response carries, "grantedScopes" what the user granted (RFC 6749 §6); "resources" and
 * "grantedResources" say the same of the resources the access token is addressed to (RFC 8707 §2.2),
 * a token request being free to narrow either and to widen neither.
 */
final readonly class GrantedAuthorization
{
    public Tenant $tenant;

    public User $user;

    public Scopes $scopes;

    public Scopes $grantedScopes;

    public ?ResourceIndicators $resources;

    public ?ResourceIndicators $grantedResources;

    /**
     * @param GrantTypeName $grantType the grant that produced this authorization, as it names itself
     * @param string|null $nonce only when the grant has one to carry (OIDC Core §3.1.3.7 step 11, §12.2)
     * @param AuthenticationSnapshot $authentication what the session had proven at the grant, written in every token
     * @param ConfirmationInterface|null $confirmation what the tokens of this response are bound to (RFC 8705 §3, RFC 9449 §6.1), null when they are bearer tokens
     * @param ResourceIndicators|null $resources the resources this response is for ("resource", RFC 8707 §2), null when the request named none
     * @param ResourceIndicators|null $grantedResources the resources the grant carries, null when it carries none
     */
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
        $this->tenant = $client->tenant;
        $this->user = $session->user;
        $this->scopes = $scopes;
        $this->grantedScopes = $grantedScopes;
        $this->resources = $resources;
        $this->grantedResources = $grantedResources;
    }

    /**
     * Who the access token of this response is addressed to (RFC 8707 §2), written by both shapes of
     * access token and rendered by the introspection of the opaque one.
     */
    public function audience(): TokenAudience
    {
        return TokenAudience::of($this->client, $this->resources);
    }

    /**
     * RFC 6749 §4.1.3, OIDC Core §3.1.3. The grant that exchanges the code names itself, here as in the
     * discovery document.
     */
    public static function fromAuthorizationCode(
        GrantTypeName $grantType,
        AuthorizationCode $code,
        ?ConfirmationInterface $confirmation = null,
        ?ResourceIndicators $resources = null,
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
        );
    }

    /**
     * RFC 6749 §6. A refresh has no nonce to carry, so the ID token it reissues carries none (OIDC Core
     * §12.2): the rule belongs here, to the grant that has none, and not to a comparison made elsewhere
     * on the name of the grant. The tokens of a refresh are bound to what the client proved at that
     * request (RFC 8705 §3), not to what it proved at the grant: a client that renews its certificate
     * gets tokens bound to the new one, and a client that stops presenting one gets bearer tokens and
     * nothing of what the bound ones could reach.
     */
    public static function fromRefreshToken(
        GrantTypeName $grantType,
        RefreshToken $token,
        ?Scopes $scopes,
        ?ConfirmationInterface $confirmation = null,
        ?ResourceIndicators $resources = null,
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
        );
    }
}

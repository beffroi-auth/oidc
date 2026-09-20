<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use function array_all;
use function array_any;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * What a verified grant entitles the client to (architecture §4.5), read by the token issuers. "scopes"
 * is what this response carries, "grantedScopes" what the user granted (RFC 6749 §6).
 */
final readonly class GrantedAuthorization
{
    public Tenant $tenant;

    public User $user;

    /**
     * @var non-empty-list<Scope>
     */
    public array $scopes;

    /**
     * @var non-empty-list<Scope>
     */
    public array $grantedScopes;

    /**
     * @param list<Scope> $scopes at least one, all among the granted ones
     * @param list<Scope> $grantedScopes
     * @param string|null $nonce only when the tokens answer a code (OIDC Core §3.1.3.7 step 11, §12.2)
     * @param AuthenticationSnapshot $authentication what the session had proven at the grant, written in every token
     */
    public function __construct(
        public GrantType $grantType,
        public Uuid $grantId,
        public Client $client,
        public AuthenticationSession $session,
        array $scopes,
        array $grantedScopes,
        public ?string $nonce,
        public ?ClaimsRequest $claimsRequest,
        public AuthenticationSnapshot $authentication,
    ) {
        if (! $session->tenant->equals($client->tenant)) {
            throw new InvalidArgumentException('An authorization binds a session and a client of the same tenant.');
        }
        if ($scopes === [] || $grantedScopes === []) {
            throw new InvalidArgumentException('An authorization carries at least one scope.');
        }
        if (! array_all($scopes, static fn (Scope $scope): bool => array_any($grantedScopes, static fn (Scope $granted): bool => $granted->equals($scope)))) {
            throw new InvalidArgumentException('The scopes of a response are among the granted ones (RFC 6749 section 6).');
        }
        if ($grantType === GrantType::RefreshToken && $nonce !== null) {
            throw new InvalidArgumentException('An ID token issued on a refresh carries no nonce (OIDC Core section 12.2).');
        }
        $this->tenant = $client->tenant;
        $this->user = $session->user;
        $this->scopes = $scopes;
        $this->grantedScopes = $grantedScopes;
    }

    /**
     * RFC 6749 §4.1.3, OIDC Core §3.1.3.
     */
    public static function fromAuthorizationCode(AuthorizationCode $code): self
    {
        return new self(
            GrantType::AuthorizationCode,
            $code->grantId,
            $code->client,
            $code->session,
            $code->scopes,
            $code->scopes,
            $code->nonce,
            $code->claimsRequest,
            $code->authentication,
        );
    }

    /**
     * RFC 6749 §6: no nonce.
     *
     * @param list<Scope>|null $scopes null for the ones of the token
     */
    public static function fromRefreshToken(RefreshToken $token, ?array $scopes): self
    {
        return new self(
            GrantType::RefreshToken,
            $token->family->grantId,
            $token->client,
            $token->session,
            $scopes ?? $token->scopes,
            $token->scopes,
            null,
            $token->claimsRequest,
            $token->authentication,
        );
    }

    public function hasScope(Scope $scope): bool
    {
        return array_any($this->scopes, static fn (Scope $granted): bool => $granted->equals($scope));
    }
}

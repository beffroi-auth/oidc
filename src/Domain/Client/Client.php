<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

use function array_any;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function in_array;
use function preg_match;
use SensitiveParameter;
use function sprintf;

/**
 * A relying party registered with a tenant (RFC 6749 §2, RFC 7591 §2). Every list is closed, no wildcard.
 * "requiresConsent = false" and "requiresPkce = false" are the named exceptions of architecture §7 and
 * decision 0008, carried by the client and by nothing global.
 */
final readonly class Client
{
    /**
     * RFC 6749 appendix A.1, without leading nor trailing space.
     */
    private const string CLIENT_ID_PATTERN = '/^[\x21-\x7E](?:[\x20-\x7E]*[\x21-\x7E])?$/';

    /**
     * @var list<RedirectUri>
     */
    public array $redirectUris;

    /**
     * @var list<RedirectUri>
     */
    public array $postLogoutRedirectUris;

    /**
     * @var list<GrantType>
     */
    public array $grantTypes;

    /**
     * @var list<Scope>
     */
    public array $allowedScopes;

    /**
     * @param PasswordHash|null $secretHash null for a public client
     * @param list<RedirectUri> $redirectUris at least one
     * @param list<RedirectUri> $postLogoutRedirectUris
     * @param list<GrantType> $grantTypes at least one; refresh_token needs authorization_code
     * @param list<Scope> $allowedScopes at least one
     * @param bool $requiresPkce false only for a confidential client (decision 0008)
     * @param ClientUri|null $backChannelLogoutUri null for a client the provider does not tell of a logout
     * @param bool $backChannelLogoutSessionRequired needs a back-channel logout URI (Back-Channel Logout 1.0 §2.2)
     * @param ClientUri|null $frontChannelLogoutUri null for a client the logout page does not load
     * @param bool $frontChannelLogoutSessionRequired needs a front-channel logout URI (Front-Channel Logout 1.0 §3)
     */
    public function __construct(
        public Tenant $tenant,
        public string $clientId,
        public string $name,
        public TokenEndpointAuthMethod $tokenEndpointAuthMethod,
        #[SensitiveParameter]
        public ?PasswordHash $secretHash,
        array $redirectUris,
        array $postLogoutRedirectUris = [],
        array $grantTypes = [GrantType::AuthorizationCode],
        ?array $allowedScopes = null,
        public bool $requiresConsent = true,
        public SignatureAlgorithm $idTokenSignedResponseAlg = SignatureAlgorithm::RS256,
        public bool $requiresPkce = true,
        public AccessTokenFormat $accessTokenFormat = AccessTokenFormat::Jwt,
        public ?ClientUri $backChannelLogoutUri = null,
        public bool $backChannelLogoutSessionRequired = false,
        public ?ClientUri $frontChannelLogoutUri = null,
        public bool $frontChannelLogoutSessionRequired = false,
    ) {
        $allowedScopes ??= [Scope::openid()];
        self::assertConsistent($clientId, $name, $tokenEndpointAuthMethod, $secretHash !== null, $redirectUris, $grantTypes, $allowedScopes, $requiresPkce, $backChannelLogoutUri !== null, $backChannelLogoutSessionRequired, $frontChannelLogoutUri !== null, $frontChannelLogoutSessionRequired);

        $sameUri = static fn (RedirectUri $a, RedirectUri $b): bool => $a->equals($b);
        $this->redirectUris = self::unique($redirectUris, $sameUri);
        $this->postLogoutRedirectUris = self::unique($postLogoutRedirectUris, $sameUri);
        $this->grantTypes = self::unique($grantTypes, static fn (GrantType $a, GrantType $b): bool => $a === $b);
        $this->allowedScopes = self::unique($allowedScopes, static fn (Scope $a, Scope $b): bool => $a->equals($b));
    }

    /**
     * The rules a registration must meet, so that a wrong configuration fails at boot.
     *
     * @param list<RedirectUri> $redirectUris
     * @param list<GrantType> $grantTypes
     * @param list<Scope> $allowedScopes
     */
    public static function assertConsistent(
        string $clientId,
        string $name,
        TokenEndpointAuthMethod $tokenEndpointAuthMethod,
        bool $hasSecret,
        array $redirectUris,
        array $grantTypes,
        array $allowedScopes,
        bool $requiresPkce = true,
        bool $hasBackChannelLogoutUri = false,
        bool $backChannelLogoutSessionRequired = false,
        bool $hasFrontChannelLogoutUri = false,
        bool $frontChannelLogoutSessionRequired = false,
    ): void {
        if (preg_match(self::CLIENT_ID_PATTERN, $clientId) !== 1) {
            throw new InvalidArgumentException(sprintf('The client identifier "%s" must be made of visible ASCII characters (RFC 6749 appendix A.1).', $clientId));
        }
        if ($name === '') {
            throw new InvalidArgumentException(sprintf('The client "%s" has a name.', $clientId));
        }
        if ($tokenEndpointAuthMethod->usesSecret() && ! $hasSecret) {
            throw new InvalidArgumentException(sprintf('The client "%s" authenticates with %s and therefore needs a secret.', $clientId, $tokenEndpointAuthMethod->value));
        }
        if (! $tokenEndpointAuthMethod->usesSecret() && $hasSecret) {
            throw new InvalidArgumentException(sprintf('The client "%s" is public (token endpoint authentication method "none") and cannot hold a secret.', $clientId));
        }
        if ($redirectUris === []) {
            throw new InvalidArgumentException(sprintf('The client "%s" registers at least one redirect URI (RFC 6749 §3.1.2.2).', $clientId));
        }
        if ($grantTypes === []) {
            throw new InvalidArgumentException(sprintf('The client "%s" is allowed at least one grant type.', $clientId));
        }
        if (in_array(GrantType::RefreshToken, $grantTypes, true) && ! in_array(GrantType::AuthorizationCode, $grantTypes, true)) {
            throw new InvalidArgumentException(sprintf('The client "%s" cannot refresh tokens it has no way to obtain: refresh_token requires authorization_code.', $clientId));
        }
        if ($allowedScopes === []) {
            throw new InvalidArgumentException(sprintf('The client "%s" is allowed at least one scope.', $clientId));
        }
        if (! $requiresPkce && ! $tokenEndpointAuthMethod->usesSecret()) {
            throw new InvalidArgumentException(sprintf('The client "%s" is public and must use PKCE (RFC 9700 section 2.1.1): requires_pkce cannot be false.', $clientId));
        }
        if ($backChannelLogoutSessionRequired && ! $hasBackChannelLogoutUri) {
            throw new InvalidArgumentException(sprintf('The client "%s" requires a "sid" in its logout token but registers no backchannel_logout_uri to receive one (Back-Channel Logout 1.0 §2.2).', $clientId));
        }
        if ($frontChannelLogoutSessionRequired && ! $hasFrontChannelLogoutUri) {
            throw new InvalidArgumentException(sprintf('The client "%s" requires an "iss" and a "sid" on its logout URI but registers no frontchannel_logout_uri to carry them (Front-Channel Logout 1.0 §3).', $clientId));
        }
    }

    public function belongsTo(Tenant $tenant): bool
    {
        return $this->tenant->equals($tenant);
    }

    public function equals(self $other): bool
    {
        return $this->clientId === $other->clientId && $this->belongsTo($other->tenant);
    }

    /**
     * RFC 6749 §2.1.
     */
    public function isPublic(): bool
    {
        return ! $this->tokenEndpointAuthMethod->usesSecret();
    }

    /**
     * RFC 6749 §3.1.2.3: byte for byte.
     */
    public function hasRedirectUri(string $redirectUri): bool
    {
        return array_any($this->redirectUris, static fn (RedirectUri $registered): bool => $registered->matches($redirectUri));
    }

    /**
     * RP-Initiated Logout §2.
     */
    public function hasPostLogoutRedirectUri(string $redirectUri): bool
    {
        return array_any($this->postLogoutRedirectUris, static fn (RedirectUri $registered): bool => $registered->matches($redirectUri));
    }

    public function allowsGrant(GrantType $grantType): bool
    {
        return in_array($grantType, $this->grantTypes, true);
    }

    public function allowsScope(Scope $scope): bool
    {
        return array_any($this->allowedScopes, static fn (Scope $allowed): bool => $allowed->equals($scope));
    }

    /**
     * @template T of object
     *
     * @param list<T> $items
     * @param callable(T, T): bool $same
     *
     * @return list<T>
     */
    private static function unique(array $items, callable $same): array
    {
        $unique = [];
        foreach ($items as $item) {
            if (! array_any($unique, static fn (object $kept): bool => $same($kept, $item))) {
                $unique[] = $item;
            }
        }

        return $unique;
    }
}

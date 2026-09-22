<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

use function array_any;
use function array_find;
use Heidi\Core\Domain\Key\SignatureAlgorithmInterface;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Certificate\CertificateIdentityInterface;
use Heidi\Oidc\Domain\Client\RequestObject\AnyRegisteredAlgorithm;
use Heidi\Oidc\Domain\Client\RequestObject\RequestObjectSigningInterface;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function in_array;
use function preg_match;
use SensitiveParameter;
use function sprintf;

/**
 * A relying party registered with a tenant (RFC 6749 §2, RFC 7591 §2). Every list is closed, no wildcard.
 * "requiresConsent = false" and "requiresPkce = false" are the named exceptions of architecture §7 and
 * decision 0008, carried by the client and by nothing global; "requiresPushedAuthorizationRequests"
 * tightens the other way, one client at a time and never by a switch of the deployment (RFC 9126 §6).
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
     * @var list<ClientUri>
     */
    public array $requestUris;

    /**
     * @var list<Scope>
     */
    public array $allowedScopes;

    /**
     * @param ClientSecretInterface|null $secret the shared secret the registered method needs, in the shape it verifies against; null when the method needs none
     * @param list<RedirectUri> $redirectUris at least one
     * @param list<RedirectUri> $postLogoutRedirectUris
     * @param list<GrantType> $grantTypes at least one; refresh_token needs authorization_code
     * @param list<Scope> $allowedScopes at least one
     * @param bool $requiresPkce false only for a confidential client (decision 0008)
     * @param bool $requiresPushedAuthorizationRequests true when the only way this client starts an authorization request is by pushing it (RFC 9126 §6)
     * @param RequestObjectSigningInterface $requestObjectSigning what the client registered in "request_object_signing_alg" (OIDC Registration §2), which its request objects are read under
     * @param list<ClientUri> $requestUris the URLs a request object of this client may be read back from (OIDC Registration §2); a "request_uri" that is none of them is refused unread
     * @param CertificateIdentityInterface|null $certificateIdentity what names the client in the certificate it presents (RFC 8705 §2.1.2), for the method that recognises it that way and for no other
     * @param ClientJwks|null $jwks the keys the client publishes inline (RFC 7591 §2); exclusive with $jwksUri
     * @param ClientUri|null $jwksUri where the keys the client publishes are read back from (RFC 7591 §2); exclusive with $jwks
     * @param SignatureAlgorithmInterface|null $idTokenSignedResponseAlg the algorithm the client registered its ID tokens and its logout tokens in (OIDC Registration §2), null for a client that registered none: the provider signs them with its default
     * @param ClientUri|null $backChannelLogoutUri null for a client the provider does not tell of a logout
     * @param bool $backChannelLogoutSessionRequired needs a back-channel logout URI (Back-Channel Logout 1.0 §2.2)
     * @param ClientUri|null $frontChannelLogoutUri null for a client the logout page does not load
     * @param bool $frontChannelLogoutSessionRequired needs a front-channel logout URI (Front-Channel Logout 1.0 §3)
     */
    public function __construct(
        public Tenant $tenant,
        public string $clientId,
        public string $name,
        public ClientAuthenticationMethodInterface $authenticationMethod,
        #[SensitiveParameter]
        public ?ClientSecretInterface $secret,
        array $redirectUris,
        array $postLogoutRedirectUris = [],
        array $grantTypes = [GrantType::AuthorizationCode],
        ?array $allowedScopes = null,
        public bool $requiresConsent = true,
        public ?SignatureAlgorithmInterface $idTokenSignedResponseAlg = null,
        public bool $requiresPkce = true,
        public AccessTokenFormat $accessTokenFormat = AccessTokenFormat::Jwt,
        public ?ClientUri $backChannelLogoutUri = null,
        public bool $backChannelLogoutSessionRequired = false,
        public ?ClientUri $frontChannelLogoutUri = null,
        public bool $frontChannelLogoutSessionRequired = false,
        public ?ClientJwks $jwks = null,
        public ?ClientUri $jwksUri = null,
        public ?CertificateIdentityInterface $certificateIdentity = null,
        public bool $requiresPushedAuthorizationRequests = false,
        public RequestObjectSigningInterface $requestObjectSigning = new AnyRegisteredAlgorithm(),
        array $requestUris = [],
    ) {
        $allowedScopes ??= [Scope::openid()];
        self::assertConsistent($clientId, $name, $authenticationMethod, $secret !== null, $redirectUris, $grantTypes, $allowedScopes, $requiresPkce, $backChannelLogoutUri !== null, $backChannelLogoutSessionRequired, $frontChannelLogoutUri !== null, $frontChannelLogoutSessionRequired, $jwks !== null, $jwksUri !== null, $certificateIdentity !== null, $requestObjectSigning);
        if ($secret !== null && $authenticationMethod instanceof SecretBearingMethodInterface && ! $authenticationMethod->accepts($secret)) {
            throw new InvalidArgumentException(sprintf('The secret of the client "%s" is not kept in a shape %s verifies against.', $clientId, $authenticationMethod->name()));
        }

        $sameUri = static fn (RedirectUri $a, RedirectUri $b): bool => $a->equals($b);
        $this->redirectUris = self::unique($redirectUris, $sameUri);
        $this->postLogoutRedirectUris = self::unique($postLogoutRedirectUris, $sameUri);
        $this->grantTypes = self::unique($grantTypes, static fn (GrantType $a, GrantType $b): bool => $a === $b);
        $this->requestUris = self::unique($requestUris, static fn (ClientUri $a, ClientUri $b): bool => $a->equals($b));
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
        ClientAuthenticationMethodInterface $authenticationMethod,
        bool $hasSecret,
        array $redirectUris,
        array $grantTypes,
        array $allowedScopes,
        bool $requiresPkce = true,
        bool $hasBackChannelLogoutUri = false,
        bool $backChannelLogoutSessionRequired = false,
        bool $hasFrontChannelLogoutUri = false,
        bool $frontChannelLogoutSessionRequired = false,
        bool $hasJwks = false,
        bool $hasJwksUri = false,
        bool $hasCertificateIdentity = false,
        RequestObjectSigningInterface $requestObjectSigning = new AnyRegisteredAlgorithm(),
    ): void {
        if (preg_match(self::CLIENT_ID_PATTERN, $clientId) !== 1) {
            throw new InvalidArgumentException(sprintf('The client identifier "%s" must be made of visible ASCII characters (RFC 6749 appendix A.1).', $clientId));
        }
        if ($name === '') {
            throw new InvalidArgumentException(sprintf('The client "%s" has a name.', $clientId));
        }
        if ($authenticationMethod instanceof SecretBearingMethodInterface && ! $hasSecret) {
            throw new InvalidArgumentException(sprintf('The client "%s" authenticates with %s and therefore needs a secret.', $clientId, $authenticationMethod->name()));
        }
        if (! $authenticationMethod instanceof SecretBearingMethodInterface && $hasSecret) {
            throw new InvalidArgumentException(sprintf('The client "%s" authenticates with %s, which proves no shared secret, and therefore cannot hold a secret.', $clientId, $authenticationMethod->name()));
        }
        if ($hasJwks && $hasJwksUri) {
            throw new InvalidArgumentException(sprintf('The client "%s" publishes its keys either inline in "jwks" or behind a "jwks_uri", never both (RFC 7591 section 2).', $clientId));
        }
        if ($authenticationMethod instanceof KeyBearingMethodInterface && ! $hasJwks && ! $hasJwksUri) {
            throw new InvalidArgumentException(sprintf('The client "%s" authenticates with %s, which verifies a signature of the client, and therefore publishes its keys in "jwks" or behind a "jwks_uri" (RFC 7591 section 2).', $clientId, $authenticationMethod->name()));
        }
        if ($requestObjectSigning->needsPublishedKeys() && ! $hasJwks && ! $hasJwksUri) {
            throw new InvalidArgumentException(sprintf('The client "%s" registers a request_object_signing_alg, whose signature is verified against a key of the client, and therefore publishes its keys in "jwks" or behind a "jwks_uri" (RFC 7591 section 2).', $clientId));
        }
        if ($authenticationMethod instanceof CertificateIdentityBearingMethodInterface && ! $hasCertificateIdentity) {
            throw new InvalidArgumentException(sprintf('The client "%s" authenticates with %s, which recognises it by what its certificate says about it, and therefore registers one of the values of RFC 8705 section 2.1.2.', $clientId, $authenticationMethod->name()));
        }
        if (! $authenticationMethod instanceof CertificateIdentityBearingMethodInterface && $hasCertificateIdentity) {
            throw new InvalidArgumentException(sprintf('The client "%s" authenticates with %s, which reads nothing of a certificate, and therefore registers none of the values of RFC 8705 section 2.1.2.', $clientId, $authenticationMethod->name()));
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
        if (! $requiresPkce && ! $authenticationMethod->authenticatesClient()) {
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
        return ! $this->authenticationMethod->authenticatesClient();
    }

    /**
     * RFC 6749 §3.1.2.3: byte for byte.
     */
    public function hasRedirectUri(string $redirectUri): bool
    {
        return array_any($this->redirectUris, static fn (RedirectUri $registered): bool => $registered->matches($redirectUri));
    }

    /**
     * OIDC Core §6.2, OIDC Registration §2 "request_uris": byte for byte, as every other URL a client
     * registers. The provider reads a request object back from a URL the client registered and from no
     * other, which is what "require_request_uri_registration" announces. What comes back is the
     * registration itself, validated at boot, so that nothing reads a URL a request wrote.
     */
    public function registeredRequestUri(string $requestUri): ?ClientUri
    {
        return array_find($this->requestUris, static fn (ClientUri $registered): bool => $registered->value === $requestUri);
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

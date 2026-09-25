<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

use function array_all;
use function array_any;
use function array_find;
use Heidi\Oidc\Domain\Ciba\DeliveryModeInterface;
use Heidi\Oidc\Domain\Ciba\NotifiesTheClientInterface;
use Heidi\Oidc\Domain\Client\Certificate\CertificateIdentityInterface;
use Heidi\Oidc\Domain\Client\RequestObject\AnyRegisteredAlgorithm;
use Heidi\Oidc\Domain\Client\RequestObject\RequestObjectSigningInterface;
use Heidi\Oidc\Domain\Resource\ResourceIndicator;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Token\TokenAudience;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function preg_match;
use function sprintf;

/**
 * What a relying party registered (RFC 7591 §2), as one value that answers for itself: every rule a
 * registration must hold is checked here, against the fields themselves, once.
 *
 * It is the same registration wherever it comes from, the configuration of a deployment or a client
 * registering itself, and it is validated before anything is built from it. What it does not hold is
 * what is not registered: the tenant it belongs to, and the shared secret in the shape the provider
 * keeps it, which are the two things a `Client` adds.
 *
 * The names it registers are read against what the provider is wired with, where the two meet, and not
 * here: a registration knows the shape of a grant name and not which names anybody serves. Whether it must
 * carry a redirect URI is one of those rules, since only the wiring says whether a grant it registered
 * sends a browser anywhere: a client that acts for itself (RFC 6749 §4.4) registers none.
 *
 * Every list is closed, no wildcard. "requiresConsent = false" and "requiresPkce = false" are the named
 * exceptions of architecture §7 and decision 0008, carried by the registration and by nothing global;
 * "requiresPushedAuthorizationRequests" tightens the other way, one client at a time and never by a
 * switch of the deployment (RFC 9126 §6).
 */
final readonly class ClientRegistration
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
     * @var list<GrantTypeName>
     */
    public array $grantTypes;

    /**
     * @var list<ClientUri>
     */
    public array $requestUris;

    /**
     * @var list<ResourceIndicator>
     */
    public array $resources;

    public Scopes $allowedScopes;

    public ResponseFormat $idToken;

    public ResponseFormat $userInfo;

    public ResponseFormat $authorizationResponse;

    /**
     * @param bool $registersASecret whether the client registered a shared secret; what shape the provider keeps it in is the business of the `Client` that holds it
     * @param list<RedirectUri> $redirectUris where the user's browser is sent back to (RFC 6749 §3.1.2); how many a client must register depends on the grants it registered, which is read where a registration meets the wiring
     * @param AccessTokenShapeInterface $accessTokenShape the shape this client receives its access tokens in (architecture §4.6), among those the provider is wired to write; which those are is read where a registration meets that wiring, as for a grant and for an authentication method
     * @param list<RedirectUri> $postLogoutRedirectUris
     * @param list<GrantTypeName> $grantTypes at least one; "authorization_code" alone for a client that registers none (RFC 7591 §2). Which names the provider serves, and which of them need another beside them, is what it is wired with and is read where a registration meets that wiring (architecture §4.8)
     * @param bool $requiresPkce false only for a confidential client (decision 0008)
     * @param bool $requiresPushedAuthorizationRequests true when the only way this client starts an authorization request is by pushing it (RFC 9126 §6)
     * @param bool $requiresSenderConstrainedTokens true when this client gets sender-constrained tokens or none at all (FAPI 2.0 Security Profile §5.3.1): a token request that proves neither a certificate nor a key is refused rather than answered with bearer tokens
     * @param bool $requiresSignedRequestObject true when an authorization request of this client is only read from a request object it signed (OIDC Registration "require_signed_request_object", FAPI 2.0 Message Signing §5.3.1)
     * @param DeliveryModeInterface|null $backchannelTokenDeliveryMode how this client is told that a backchannel request has been answered (CIBA Core §4), among the modes the provider is wired with; null for a client of no such flow, which is every client that does not ask for one. There is no default: a mode nobody registered would make a client of another flow a client of this one by accident
     * @param ClientUri|null $backchannelClientNotificationEndpoint where this provider calls that client back (CIBA Core §7.1), for a mode where it does and for no other
     * @param list<ResourceIndicator> $resources the resources this client may ask a token for ("resource", RFC 8707 §2); a closed list like every other, so a resource outside it is "invalid_target". A client that registers none asks for none and its tokens are addressed to itself
     * @param RequestObjectSigningInterface $requestObjectSigning what the client registered in "request_object_signing_alg" (OIDC Registration §2), which its request objects are read under
     * @param list<ClientUri> $requestUris the URLs a request object of this client may be read back from (OIDC Registration §2); a "request_uri" that is none of them is refused unread
     * @param CertificateIdentityInterface|null $certificateIdentity what names the client in the certificate it presents (RFC 8705 §2.1.2), for the method that recognises it that way and for no other
     * @param ClientJwks|null $jwks the keys the client publishes inline (RFC 7591 §2); exclusive with $jwksUri
     * @param ClientUri|null $jwksUri where the keys the client publishes are read back from (RFC 7591 §2); exclusive with $jwks
     * @param ResponseFormat|null $idToken the shape the client registered for its ID tokens (OIDC Core §3.1.3.7), which its logout tokens are signed like; null for the ordinary one, signed with what the provider signs with and not encrypted
     * @param ResponseFormat|null $authorizationResponse the shape the client registered for its signed authorization responses (JARM §3), null for the ordinary one
     * @param ResponseFormat|null $userInfo the shape the client registered for the UserInfo answer (OIDC Core §5.3.2); null for the plain JSON, which is what a client that registered nothing receives
     * @param ClientUri|null $backChannelLogoutUri null for a client the provider does not tell of a logout
     * @param bool $backChannelLogoutSessionRequired needs a back-channel logout URI (Back-Channel Logout 1.0 §2.2)
     * @param ClientUri|null $frontChannelLogoutUri null for a client the logout page does not load
     * @param bool $frontChannelLogoutSessionRequired needs a front-channel logout URI (Front-Channel Logout 1.0 §3)
     *
     * @throws InvalidArgumentException when the registration does not hold together
     */
    public function __construct(
        public string $clientId,
        public string $name,
        public ClientAuthenticationMethodInterface $authenticationMethod,
        public bool $registersASecret,
        array $redirectUris,
        public AccessTokenShapeInterface $accessTokenShape,
        array $postLogoutRedirectUris = [],
        array $grantTypes = [new GrantTypeName('authorization_code')],
        ?Scopes $allowedScopes = null,
        public bool $requiresConsent = true,
        ?ResponseFormat $idToken = null,
        public bool $requiresPkce = true,
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
        ?ResponseFormat $authorizationResponse = null,
        ?ResponseFormat $userInfo = null,
        public bool $requiresSenderConstrainedTokens = false,
        public bool $requiresSignedRequestObject = false,
        array $resources = [],
        public ?DeliveryModeInterface $backchannelTokenDeliveryMode = null,
        public ?ClientUri $backchannelClientNotificationEndpoint = null,
    ) {
        $this->allowedScopes = $allowedScopes ?? new Scopes([Scope::openid()]);
        $this->idToken = $idToken ?? ResponseFormat::signed();
        $this->authorizationResponse = $authorizationResponse ?? ResponseFormat::signed();
        $this->userInfo = $userInfo ?? ResponseFormat::unsigned();

        $sameUri = static fn (RedirectUri $a, RedirectUri $b): bool => $a->equals($b);
        $this->redirectUris = self::unique($redirectUris, $sameUri);
        $this->postLogoutRedirectUris = self::unique($postLogoutRedirectUris, $sameUri);
        $this->grantTypes = self::unique($grantTypes, static fn (GrantTypeName $a, GrantTypeName $b): bool => $a->equals($b));
        $this->requestUris = self::unique($requestUris, static fn (ClientUri $a, ClientUri $b): bool => $a->equals($b));
        $this->resources = self::unique($resources, static fn (ResourceIndicator $a, ResourceIndicator $b): bool => $a->equals($b));

        $this->assertHoldsTogether();
    }

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

    public function allowsGrant(GrantTypeName $grantType): bool
    {
        return array_any($this->grantTypes, static fn (GrantTypeName $registered): bool => $registered->equals($grantType));
    }

    /**
     * RFC 8707 §2.1: what this client may ask a token for, compared byte for byte as every other URI it
     * registers. A client that registered none may ask for none.
     */
    public function allowsResources(ResourceIndicators $resources): bool
    {
        return array_all(
            $resources->all,
            fn (ResourceIndicator $asked): bool => array_any($this->resources, static fn (ResourceIndicator $registered): bool => $registered->equals($asked)),
        );
    }

    /**
     * What a token of this client may be addressed to (RFC 8707 §2): one of the resources it registered,
     * or the client itself when the request named none. Read where a token is read back, so that a value
     * this provider would never have written is refused before anything is believed of it.
     */
    public function mayBeAddressedTo(TokenAudience $audience): bool
    {
        return array_all(
            $audience->values,
            fn (string $value): bool => (
                $value === $this->clientId
                || array_any(
                    $this->resources,
                    static fn (ResourceIndicator $registered): bool => $registered->value === $value,
                )
            ),
        );
    }

    /**
     * Whether any of the three documents the provider writes for this client is addressed to a key of
     * its own, which is what makes published keys necessary.
     */
    public function registersAnEncryption(): bool
    {
        return $this->idToken->isEncrypted() || $this->authorizationResponse->isEncrypted() || $this->userInfo->isEncrypted();
    }

    /**
     * Whether the client publishes its keys at all, inline or behind a URL (RFC 7591 §2).
     */
    public function publishesKeys(): bool
    {
        return $this->jwks !== null || $this->jwksUri !== null;
    }

    /**
     * @throws InvalidArgumentException
     */
    private function assertHoldsTogether(): void
    {
        if (preg_match(self::CLIENT_ID_PATTERN, $this->clientId) !== 1) {
            throw new InvalidArgumentException(sprintf(
                'The client identifier "%s" must be made of visible ASCII characters (RFC 6749 appendix A.1).',
                $this->clientId,
            ));
        }
        if ($this->name === '') {
            throw new InvalidArgumentException(sprintf('The client "%s" has a name.', $this->clientId));
        }
        if ($this->authenticationMethod instanceof SecretBearingMethodInterface && ! $this->registersASecret) {
            throw new InvalidArgumentException(sprintf(
                'The client "%s" authenticates with %s and therefore needs a secret.',
                $this->clientId,
                $this->authenticationMethod->name(),
            ));
        }
        if (! $this->authenticationMethod instanceof SecretBearingMethodInterface && $this->registersASecret) {
            throw new InvalidArgumentException(sprintf(
                'The client "%s" authenticates with %s, which proves no shared secret, and therefore cannot hold a secret.',
                $this->clientId,
                $this->authenticationMethod->name(),
            ));
        }
        if ($this->jwks !== null && $this->jwksUri !== null) {
            throw new InvalidArgumentException(sprintf(
                'The client "%s" publishes its keys either inline in "jwks" or behind a "jwks_uri", never both (RFC 7591 section 2).',
                $this->clientId,
            ));
        }
        if ($this->authenticationMethod instanceof KeyBearingMethodInterface && ! $this->publishesKeys()) {
            throw new InvalidArgumentException(sprintf(
                'The client "%s" authenticates with %s, which verifies a signature of the client, and therefore publishes its keys in "jwks" or behind a "jwks_uri" (RFC 7591 section 2).',
                $this->clientId,
                $this->authenticationMethod->name(),
            ));
        }
        if ($this->requestObjectSigning->needsPublishedKeys() && ! $this->publishesKeys()) {
            throw new InvalidArgumentException(sprintf(
                'The client "%s" registers a request_object_signing_alg, whose signature is verified against a key of the client, and therefore publishes its keys in "jwks" or behind a "jwks_uri" (RFC 7591 section 2).',
                $this->clientId,
            ));
        }
        if ($this->registersAnEncryption() && ! $this->publishesKeys()) {
            throw new InvalidArgumentException(sprintf(
                'The client "%s" registers an encrypted response, which is addressed to a key of the client, and therefore publishes its keys in "jwks" or behind a "jwks_uri" (RFC 7591 section 2).',
                $this->clientId,
            ));
        }
        if ($this->authenticationMethod instanceof CertificateIdentityBearingMethodInterface && $this->certificateIdentity === null) {
            throw new InvalidArgumentException(sprintf(
                'The client "%s" authenticates with %s, which recognises it by what its certificate says about it, and therefore registers one of the values of RFC 8705 section 2.1.2.',
                $this->clientId,
                $this->authenticationMethod->name(),
            ));
        }
        if (! $this->authenticationMethod instanceof CertificateIdentityBearingMethodInterface && $this->certificateIdentity !== null) {
            throw new InvalidArgumentException(sprintf(
                'The client "%s" authenticates with %s, which reads nothing of a certificate, and therefore registers none of the values of RFC 8705 section 2.1.2.',
                $this->clientId,
                $this->authenticationMethod->name(),
            ));
        }
        if ($this->grantTypes === []) {
            throw new InvalidArgumentException(sprintf('The client "%s" is allowed at least one grant type.', $this->clientId));
        }
        if (! $this->requiresPkce && $this->isPublic()) {
            throw new InvalidArgumentException(sprintf(
                'The client "%s" is public and must use PKCE (RFC 9700 section 2.1.1): requires_pkce cannot be false.',
                $this->clientId,
            ));
        }
        if ($this->backChannelLogoutSessionRequired && $this->backChannelLogoutUri === null) {
            throw new InvalidArgumentException(sprintf(
                'The client "%s" requires a "sid" in its logout token but registers no backchannel_logout_uri to receive one (Back-Channel Logout 1.0 §2.2).',
                $this->clientId,
            ));
        }
        if ($this->frontChannelLogoutSessionRequired && $this->frontChannelLogoutUri === null) {
            throw new InvalidArgumentException(sprintf(
                'The client "%s" requires an "iss" and a "sid" on its logout URI but registers no frontchannel_logout_uri to carry them (Front-Channel Logout 1.0 §3).',
                $this->clientId,
            ));
        }
        if ($this->backchannelTokenDeliveryMode instanceof NotifiesTheClientInterface && $this->backchannelClientNotificationEndpoint === null) {
            throw new InvalidArgumentException(sprintf(
                'The client "%s" registers the "%s" backchannel token delivery mode, where the provider calls it back, but registers no backchannel_client_notification_endpoint to be called at (CIBA Core section 7.1).',
                $this->clientId,
                $this->backchannelTokenDeliveryMode->name(),
            ));
        }
        if (! $this->backchannelTokenDeliveryMode instanceof NotifiesTheClientInterface && $this->backchannelClientNotificationEndpoint !== null) {
            throw new InvalidArgumentException(sprintf(
                'The client "%s" registers a backchannel_client_notification_endpoint but no backchannel token delivery mode where the provider calls it (CIBA Core section 7.1).',
                $this->clientId,
            ));
        }
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

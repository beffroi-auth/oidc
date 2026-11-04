<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use function array_all;
use function array_any;
use function array_find;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Ciba\DeliveryModeInterface;
use Beffroi\Oidc\Domain\Ciba\NotifiesTheClientInterface;
use Beffroi\Oidc\Domain\Client\Certificate\CertificateIdentityInterface;
use Beffroi\Oidc\Domain\Client\RequestObject\AnyRegisteredAlgorithm;
use Beffroi\Oidc\Domain\Client\RequestObject\RequestObjectSigningInterface;
use Beffroi\Oidc\Domain\Exchange\MayAct;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\TokenAudience;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function in_array;
use function preg_match;
use function sprintf;

/**
 * RFC 7591 §2
 */
final readonly class ClientRegistration
{
    /**
     * RFC 6749 appendix A.1, without a leading or trailing space
     */
    private const string CLIENT_ID_PATTERN = '/^[\x21-\x7E](?:[\x20-\x7E]*[\x21-\x7E])?$/D';

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
     * @var list<RequestUri>
     */
    public array $requestUris;

    /**
     * @var list<ResourceIndicator>
     */
    public array $resources;

    /**
     * @var list<non-empty-string>
     */
    public array $authorizationDetailsTypes;

    public Scopes $allowedScopes;

    public ResponseFormat $idToken;

    public ResponseFormat $userInfo;

    public ResponseFormat $authorizationResponse;

    /**
     * @param list<RedirectUri> $redirectUris
     * @param list<RedirectUri> $postLogoutRedirectUris
     * @param list<GrantTypeName> $grantTypes at least one
     * @param non-empty-string|null $subjectType
     * @param list<ResourceIndicator> $resources
     * @param list<string> $authorizationDetailsTypes
     * @param list<RequestUri> $requestUris
     *
     * @throws InvalidArgumentException
     */
    public function __construct(
        public string $clientId,
        public ClientPresentation $presentation,
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
        public ?TokenExchange $tokenExchange = null,
        public ?MayAct $mayAct = null,
        array $authorizationDetailsTypes = [],
        public bool $requiresCertificateBoundTokens = false,
        public ?string $subjectType = null,
        public ?ClientUri $sectorIdentifierUri = null,
        public ?InitiateLoginUri $initiateLoginUri = null,
        public ?string $softwareId = null,
        public ?string $softwareVersion = null,
    ) {
        $this->allowedScopes = $allowedScopes ?? new Scopes([Scope::openid()]);
        $this->idToken = $idToken ?? ResponseFormat::signed();
        $this->authorizationResponse = $authorizationResponse ?? ResponseFormat::signed();
        $this->userInfo = $userInfo ?? ResponseFormat::unsigned();

        $sameUri = static fn (RedirectUri $a, RedirectUri $b): bool => $a->equals($b);
        $this->redirectUris = self::unique($redirectUris, $sameUri);
        $this->postLogoutRedirectUris = self::unique($postLogoutRedirectUris, $sameUri);
        $this->grantTypes = self::unique($grantTypes, static fn (GrantTypeName $a, GrantTypeName $b): bool => $a->equals($b));
        $this->requestUris = self::unique($requestUris, static fn (RequestUri $a, RequestUri $b): bool => $a->equals($b));
        $this->resources = self::unique($resources, static fn (ResourceIndicator $a, ResourceIndicator $b): bool => $a->equals($b));
        $this->authorizationDetailsTypes = self::uniqueNames($authorizationDetailsTypes);

        $this->assertHoldsTogether();
    }

    public function isPublic(): bool
    {
        return ! $this->authenticationMethod->authenticatesClient();
    }

    /**
     * RFC 6749 §3.1.2.3, RFC 8252 §7.3
     *
     * The port of a loopback redirection may vary for a public client only.
     */
    public function hasRedirectUri(string $redirectUri): bool
    {
        return array_any(
            $this->redirectUris,
            fn (RedirectUri $registered): bool => $registered->matches($redirectUri) || $this->isPublic() && $registered->matchesOnAnyPort($redirectUri),
        );
    }

    /**
     * OIDC Core §6.2, OIDC Registration §2
     *
     * Returns the registered value, so that nothing fetches a URL a request wrote.
     */
    public function registeredRequestUri(string $requestUri): ?RequestUri
    {
        return array_find($this->requestUris, static fn (RequestUri $registered): bool => $registered->value === $requestUri);
    }

    /**
     * RP-Initiated Logout §2, RFC 8252 §7.3
     */
    public function hasPostLogoutRedirectUri(string $redirectUri): bool
    {
        return array_any(
            $this->postLogoutRedirectUris,
            fn (RedirectUri $registered): bool => $registered->matches($redirectUri) || $this->isPublic() && $registered->matchesOnAnyPort($redirectUri),
        );
    }

    public function allowsGrant(GrantTypeName $grantType): bool
    {
        return array_any($this->grantTypes, static fn (GrantTypeName $registered): bool => $registered->equals($grantType));
    }

    /**
     * RFC 8707 §2.1
     */
    public function allowsResources(ResourceIndicators $resources): bool
    {
        return array_all(
            $resources->all,
            fn (ResourceIndicator $asked): bool => array_any($this->resources, static fn (ResourceIndicator $registered): bool => $registered->equals($asked)),
        );
    }

    /**
     * RFC 9396 §11
     */
    public function allowsAuthorizationDetails(AuthorizationDetails $details): bool
    {
        return array_all(
            $details->types(),
            fn (string $type): bool => in_array($type, $this->authorizationDetailsTypes, true),
        );
    }

    /**
     * RFC 8707 §2
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

    public function registersAnEncryption(): bool
    {
        return $this->idToken->isEncrypted() || $this->authorizationResponse->isEncrypted() || $this->userInfo->isEncrypted();
    }

    public function publishesKeys(): bool
    {
        return $this->jwks !== null || $this->jwksUri !== null;
    }

    public function publishedKeys(): ClientJwks|ClientUri|null
    {
        return $this->jwks ?? $this->jwksUri;
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
        if ($this->presentation->name === '') {
            throw new InvalidArgumentException(sprintf('The client "%s" has a name.', $this->clientId));
        }
        if (in_array('', $this->presentation->contacts, true)) {
            throw new InvalidArgumentException(sprintf('The client "%s" registers no empty contact (OIDC Registration section 2).', $this->clientId));
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
        if ($this->requiresSignedRequestObject && $this->requestObjectSigning->acceptsUnsigned()) {
            throw new InvalidArgumentException(sprintf(
                'The client "%s" has its requests read only from a request object it signed (require_signed_request_object), and therefore registers no request_object_signing_alg under which an unsigned one is read (RFC 9101 section 10.5).',
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
        foreach ([...$this->redirectUris, ...$this->postLogoutRedirectUris] as $redirectUri) {
            if ($this->isPublic() && $redirectUri->isPlainHttpOnAName()) {
                throw new InvalidArgumentException(sprintf(
                    'The client "%s" is public and sends its browser back to "%s" in plain HTTP: a native client registers the loopback interface by its IP literal, 127.0.0.1 or [::1], and never by a name (RFC 8252 section 8.3).',
                    $this->clientId,
                    $redirectUri->value,
                ));
            }
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
     * @param list<string> $names
     *
     * @throws InvalidArgumentException when one of them is empty
     *
     * @return list<non-empty-string>
     */
    private function uniqueNames(array $names): array
    {
        $unique = [];
        foreach ($names as $name) {
            if ($name === '') {
                throw new InvalidArgumentException(sprintf('The client "%s" registers no empty name in a closed list.', $this->clientId));
            }
            if (! in_array($name, $unique, true)) {
                $unique[] = $name;
            }
        }

        return $unique;
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

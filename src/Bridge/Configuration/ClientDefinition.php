<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\Configuration;

use function array_any;
use function array_diff;
use function array_find;
use function array_keys;
use function array_search;
use Heidi\Core\Domain\Key\SignatureAlgorithmInterface;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\UnsupportedAlgorithmException;
use Heidi\Core\Port\ContentEncryptionAlgorithmsInterface;
use Heidi\Core\Port\KeyEncryptionAlgorithmsInterface;
use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Application\Client\Method\SecretKeepingMethodInterface;
use Heidi\Oidc\Application\Client\MethodNames;
use Heidi\Oidc\Application\Key\AlgorithmNames;
use Heidi\Oidc\Application\Token\GrantNames;
use Heidi\Oidc\Application\Token\ShapeNames;
use Heidi\Oidc\Domain\Client\AccessTokenShapeInterface;
use Heidi\Oidc\Domain\Client\Certificate\CertificateIdentities;
use Heidi\Oidc\Domain\Client\Certificate\CertificateIdentityInterface;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Heidi\Oidc\Domain\Client\ClientJwks;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Domain\Client\ClientSecretInterface;
use Heidi\Oidc\Domain\Client\ClientUri;
use Heidi\Oidc\Domain\Client\GrantTypeName;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Client\RequestObject\AnyRegisteredAlgorithm;
use Heidi\Oidc\Domain\Client\RequestObject\OneRegisteredAlgorithm;
use Heidi\Oidc\Domain\Client\RequestObject\RequestObjectSigningInterface;
use Heidi\Oidc\Domain\Client\RequestObject\UnsignedRequestObjects;
use Heidi\Oidc\Domain\Resource\ResourceIndicator;
use Heidi\Oidc\Domain\Client\ResponseEncryption;
use Heidi\Oidc\Domain\Client\ResponseFormat;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
use Heidi\Oidc\Exception\UnreadableCertificateException;
use Heidi\Oidc\Port\CertificateReaderInterface;
use Heidi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Heidi\Oidc\Port\ServedAccessTokenShapesInterface;
use Heidi\Oidc\Port\ServedGrantsInterface;
use function implode;
use function is_array;
use function is_bool;
use function is_string;
use function preg_match;
use SensitiveParameter;
use function sprintf;

/**
 * One client as the configuration declares it (architecture §5.1), read strictly, nothing cast. The
 * secret stays in clear until the client is built.
 */
final readonly class ClientDefinition
{
    /**
     * RFC 6749 appendix A.2, at least 32 characters (RFC 6819 §5.1.4.2.2).
     */
    private const string SECRET_PATTERN = '/^[\x21-\x7E]{32,}$/';

    /**
     * What a client that declares no "grant_types" is registered for: the browser flow and the renewal
     * that goes with it, which is what a relying party of this provider comes for. RFC 7591 §2 defaults
     * to "authorization_code" alone; a deployment that wants that writes it, and one that wants more
     * names what it is wired with.
     *
     * @var non-empty-list<string>
     */
    public const array DEFAULT_GRANT_TYPES = ['authorization_code', 'refresh_token'];

    private const array KEYS = [
        'name',
        'secret',
        'redirect_uris',
        'post_logout_redirect_uris',
        'grant_types',
        'allowed_scopes',
        'token_endpoint_auth_method',
        'requires_consent',
        'id_token_signed_response_alg',
        'id_token_encrypted_response_alg',
        'id_token_encrypted_response_enc',
        'userinfo_signed_response_alg',
        'userinfo_encrypted_response_alg',
        'userinfo_encrypted_response_enc',
        'authorization_signed_response_alg',
        'authorization_encrypted_response_alg',
        'authorization_encrypted_response_enc',
        'requires_pkce',
        'require_pushed_authorization_requests',
        'require_sender_constrained_tokens',
        'require_signed_request_object',
        'access_token_format',
        'backchannel_logout_uri',
        'backchannel_logout_session_required',
        'frontchannel_logout_uri',
        'frontchannel_logout_session_required',
        'jwks',
        'jwks_uri',
        'request_object_signing_alg',
        'request_uris',
        'resources',
        ...CertificateIdentities::NAMES,
    ];

    private function __construct(
        #[SensitiveParameter]
        private ?string $secret,
        public ClientRegistration $registration,
    ) {
    }

    /**
     * @param array<string, mixed> $definition the keys of architecture §5.1, in snake_case
     * @param SignatureAlgorithmsInterface $algorithms what the provider signs with: a client registers one of those names, or none and takes the default
     * @param KeyEncryptionAlgorithmsInterface $keyEncryption what the provider encrypts a document to a client with: a client registers one of those names, or none and receives nothing encrypted
     * @param ContentEncryptionAlgorithmsInterface $contentEncryption what the payload of such a document is encrypted with
     * @param ClientAuthenticationMethodsInterface $methods what the provider authenticates clients with: a client registers one of those names
     * @param ServedGrantsInterface $grants what the provider serves at its token endpoint: a client registers those names and no other
     * @param ServedAccessTokenShapesInterface $shapes what the provider writes its access tokens in: a client registers one of those names, or none and takes the first
     * @param CertificateReaderInterface $certificates what writes a registered distinguished name the way it will be read out of a certificate (RFC 8705 §2.1.2)
     */
    public static function fromArray(
        string $clientId,
        array $definition,
        SignatureAlgorithmsInterface $algorithms,
        ClientAuthenticationMethodsInterface $methods,
        ServedGrantsInterface $grants,
        ServedAccessTokenShapesInterface $shapes,
        CertificateReaderInterface $certificates,
        KeyEncryptionAlgorithmsInterface $keyEncryption,
        ContentEncryptionAlgorithmsInterface $contentEncryption,
    ): self {
        $unknown = array_diff(array_keys($definition), self::KEYS);
        if ($unknown !== []) {
            throw new InvalidArgumentException(sprintf('The client "%s" has unknown keys: %s.', $clientId, implode(', ', $unknown)));
        }

        $secret = $definition['secret'] ?? null;
        if ($secret !== null) {
            if (! is_string($secret)) {
                throw new InvalidArgumentException(sprintf('The secret of the client "%s" must be a string.', $clientId));
            }
            if (preg_match(self::SECRET_PATTERN, $secret) !== 1) {
                throw new InvalidArgumentException(sprintf(
                    'The secret of the client "%s" must be at least 32 visible ASCII characters long; generate it, do not choose it.',
                    $clientId,
                ));
            }
        }

        $method = self::method($clientId, $definition, $methods);

        $requiresConsent = self::flag($clientId, 'requires_consent', $definition, true);
        $requiresPkce = self::flag($clientId, 'requires_pkce', $definition, true);

        $name = $definition['name'] ?? $clientId;
        if (! is_string($name)) {
            throw new InvalidArgumentException(sprintf('The name of the client "%s" must be a string.', $clientId));
        }

        $redirectUris = array_map(
            static fn (string $uri): RedirectUri => new RedirectUri($uri),
            self::stringList($clientId, 'redirect_uris', $definition['redirect_uris'] ?? []),
        );
        $postLogoutRedirectUris = array_map(
            static fn (string $uri): RedirectUri => new RedirectUri($uri),
            self::stringList($clientId, 'post_logout_redirect_uris', $definition['post_logout_redirect_uris'] ?? []),
        );
        $grantTypes = self::grantTypes($clientId, $definition, $grants);
        $allowedScopes = new Scopes(array_map(
            static fn (string $scope): Scope => new Scope($scope),
            self::stringList($clientId, 'allowed_scopes', $definition['allowed_scopes'] ?? ['openid', 'profile', 'email']),
        ));
        $idToken = ResponseFormat::signed(
            self::algorithm($clientId, 'id_token_signed_response_alg', $definition, $algorithms),
            self::encryption($clientId, 'id_token', $definition, $keyEncryption, $contentEncryption),
        );
        $authorizationResponse = ResponseFormat::signed(
            self::algorithm($clientId, 'authorization_signed_response_alg', $definition, $algorithms),
            self::encryption($clientId, 'authorization', $definition, $keyEncryption, $contentEncryption),
        );
        $userInfoEncryption = self::encryption($clientId, 'userinfo', $definition, $keyEncryption, $contentEncryption);
        $userInfoSignature = $definition['userinfo_signed_response_alg'] ?? null;
        $userInfo = $userInfoSignature === null
            ? ResponseFormat::unsigned($userInfoEncryption)
            : ResponseFormat::signed(self::algorithm($clientId, 'userinfo_signed_response_alg', $definition, $algorithms), $userInfoEncryption);

        $requiresPushedAuthorizationRequests = self::flag($clientId, 'require_pushed_authorization_requests', $definition);
        $requiresSenderConstrainedTokens = self::flag($clientId, 'require_sender_constrained_tokens', $definition);
        $requiresSignedRequestObject = self::flag($clientId, 'require_signed_request_object', $definition);

        $accessTokenShape = self::accessTokenShape($clientId, $definition, $shapes);

        $jwks = self::jwks($clientId, $definition);
        $jwksUri = self::clientUri($clientId, 'jwks_uri', $definition);

        $backChannelLogoutUri = self::clientUri($clientId, 'backchannel_logout_uri', $definition);
        $backChannelLogoutSessionRequired = self::flag($clientId, 'backchannel_logout_session_required', $definition);
        $frontChannelLogoutUri = self::clientUri($clientId, 'frontchannel_logout_uri', $definition);
        $frontChannelLogoutSessionRequired = self::flag($clientId, 'frontchannel_logout_session_required', $definition);

        $certificateIdentity = self::certificateIdentity($clientId, $definition, $certificates);

        $requestObjectSigning = self::requestObjectSigning($clientId, $definition, $algorithms);
        $requestUris = array_map(
            static fn (string $uri): ClientUri => new ClientUri($uri),
            self::stringList($clientId, 'request_uris', $definition['request_uris'] ?? []),
        );
        $resources = array_map(
            static fn (string $uri): ResourceIndicator => new ResourceIndicator($uri),
            self::stringList($clientId, 'resources', $definition['resources'] ?? []),
        );

        $registration = new ClientRegistration(
            $clientId,
            $name,
            $method,
            $secret !== null,
            $redirectUris,
            $accessTokenShape,
            $postLogoutRedirectUris,
            $grantTypes,
            $allowedScopes,
            $requiresConsent,
            $idToken,
            $requiresPkce,
            $backChannelLogoutUri,
            $backChannelLogoutSessionRequired,
            $frontChannelLogoutUri,
            $frontChannelLogoutSessionRequired,
            $jwks,
            $jwksUri,
            $certificateIdentity,
            $requiresPushedAuthorizationRequests,
            $requestObjectSigning,
            $requestUris,
            $authorizationResponse,
            $userInfo,
            $requiresSenderConstrainedTokens,
            $requiresSignedRequestObject,
            $resources,
        );
        foreach ([$idToken, $userInfo, $authorizationResponse] as $format) {
            self::assertAddressable($clientId, $format, $jwks);
        }

        return new self($secret, $registration);
    }

    /**
     * A JWS algorithm a client registers for a kind of thing the provider signs for it (OIDC
     * Registration §2, JARM §3): one of the names the provider is wired with, or none and the default it
     * signs with. Written once for the two options, so that they cannot read their names differently.
     *
     * @param array<string, mixed> $definition
     */
    private static function algorithm(
        string $clientId,
        string $option,
        array $definition,
        SignatureAlgorithmsInterface $algorithms,
    ): SignatureAlgorithmInterface {
        $name = self::text($clientId, $option, $definition);
        if ($name === null) {
            return $algorithms->defaultAlgorithm();
        }
        try {
            return $algorithms->named($name);
        } catch (UnsupportedAlgorithmException $exception) {
            throw self::oneOf($clientId, $option, AlgorithmNames::of($algorithms->all()), $exception);
        }
    }

    /**
     * The pair a client registers to have one kind of document encrypted for it (OIDC Registration §2,
     * JARM §3): the "alg" the content encryption key is wrapped under, and the "enc" the payload is
     * encrypted with. Both or neither, and never one alone: §2 lets an "enc" be left out and defaults it
     * to "A128CBC-HS256", which this provider is not wired with, so taking that default would accept at
     * boot a registration that fails on the first document. Written once for the three kinds, so that
     * they cannot read their names differently.
     *
     * @param string $prefix the kind of document, as the registration names it
     * @param array<string, mixed> $definition
     */
    private static function encryption(
        string $clientId,
        string $prefix,
        array $definition,
        KeyEncryptionAlgorithmsInterface $keyEncryption,
        ContentEncryptionAlgorithmsInterface $contentEncryption,
    ): ?ResponseEncryption {
        $algorithmOption = $prefix . '_encrypted_response_alg';
        $methodOption = $prefix . '_encrypted_response_enc';
        $algorithmName = $definition[$algorithmOption] ?? null;
        $methodName = $definition[$methodOption] ?? null;
        if ($algorithmName === null && $methodName === null) {
            return null;
        }
        if ($algorithmName === null || $methodName === null) {
            throw new InvalidArgumentException(sprintf(
                'The client "%s" registers %s without %s; a document is encrypted to a key under an "alg" and its payload under an "enc", and this provider takes no default for either.',
                $clientId,
                $algorithmName === null ? $methodOption : $algorithmOption,
                $algorithmName === null ? $algorithmOption : $methodOption,
            ));
        }
        if (! is_string($algorithmName) || ! is_string($methodName)) {
            throw new InvalidArgumentException(sprintf(
                'The %s and %s options of the client "%s" must be strings.',
                $algorithmOption,
                $methodOption,
                $clientId,
            ));
        }

        try {
            $algorithm = $keyEncryption->named($algorithmName);
        } catch (UnsupportedAlgorithmException $exception) {
            throw self::oneOf($clientId, $algorithmOption, AlgorithmNames::of($keyEncryption->all()), $exception);
        }

        try {
            $method = $contentEncryption->named($methodName);
        } catch (UnsupportedAlgorithmException $exception) {
            throw self::oneOf($clientId, $methodOption, AlgorithmNames::of($contentEncryption->all()), $exception);
        }

        return new ResponseEncryption($algorithm, $method);
    }

    /**
     * A client that asks for an encrypted document publishes a key such a document can be addressed to.
     * A set given inline is read here and must hold one; a set behind a "jwks_uri" is read when a document
     * is minted, and all a boot can ask of it is that the client publishes one somewhere, which the
     * consistency rules of the client do.
     */
    private static function assertAddressable(string $clientId, ResponseFormat $format, ?ClientJwks $jwks): void
    {
        $encryption = $format->encryption;
        if ($encryption === null || $jwks === null) {
            return;
        }
        if ($jwks->encryptionKeyFor($encryption->algorithm) !== null) {
            return;
        }

        throw new InvalidArgumentException(sprintf(
            'The client "%s" registers a response encrypted under "%s" but publishes no key it can be addressed to: its "jwks" holds no %s key that is not reserved for signing.',
            $clientId,
            $encryption->algorithm->name(),
            $encryption->algorithm->keyType(),
        ));
    }

    public function hasSecret(): bool
    {
        return $this->secret !== null;
    }

    /**
     * The registered secret in the shape the method it registered verifies against. As costly as hashing
     * a password when the method keeps a hash: once per process.
     *
     * @throws LogicException for a client whose method proves no secret
     */
    public function keepSecret(PasswordHasherInterface $hasher): ClientSecretInterface
    {
        $method = $this->registration->authenticationMethod;
        if ($this->secret === null || ! $method instanceof SecretKeepingMethodInterface) {
            throw new LogicException(sprintf('The client "%s" registers no secret to keep.', $this->registration->clientId));
        }

        return $method->keep($this->secret, $hasher);
    }

    public function toClient(Tenant $tenant, ?ClientSecretInterface $secret): Client
    {
        return new Client($tenant, $this->registration, $secret);
    }

    /**
     * The method the client registers, among those the provider is wired with (issue #98): a name
     * nothing authenticates with fails at boot with the list of the wired ones, because the
     * configuration tree cannot know that list.
     *
     * @param array<string, mixed> $definition
     */
    private static function method(string $clientId, array $definition, ClientAuthenticationMethodsInterface $methods): ClientAuthenticationMethodInterface
    {
        $wired = $methods->clientAuthenticationMethods();

        return self::named($clientId, 'token_endpoint_auth_method', $definition, $wired, MethodNames::of($wired));
    }

    /**
     * The shape the client registers its access tokens in, among those the provider is wired to write
     * (issue #239): a name nothing writes fails at boot with the list of the wired ones, because the
     * configuration tree cannot know that list. A client that registers none takes the first wired
     * shape, as it takes the first wired authentication method.
     *
     * @param array<string, mixed> $definition
     */
    private static function accessTokenShape(string $clientId, array $definition, ServedAccessTokenShapesInterface $shapes): AccessTokenShapeInterface
    {
        $wired = $shapes->servedAccessTokenShapes();

        return self::named($clientId, 'access_token_format', $definition, $wired, ShapeNames::of($wired));
    }

    /**
     * One of the things the provider is wired with, picked by the name the client registered, or the
     * first of them when the client registered none. Written once for the two options that read a wired
     * list this way, so that they cannot take a name, take a default or refuse differently; the names
     * are read from the things themselves and never written again here.
     *
     * @template T of object
     *
     * @param array<string, mixed> $definition
     * @param non-empty-list<T> $wired
     * @param non-empty-list<string> $names what each of them calls itself, in the same order
     *
     * @throws InvalidArgumentException when the client registered a name nothing is wired with
     *
     * @return T
     */
    private static function named(string $clientId, string $option, array $definition, array $wired, array $names): object
    {
        $name = self::text($clientId, $option, $definition);
        if ($name === null) {
            return $wired[0];
        }
        $at = array_search($name, $names, true);

        return $at === false ? throw self::oneOf($clientId, $option, $names) : $wired[$at];
    }

    /**
     * The grants the client registers, among those the provider serves (issue #98): a name nothing
     * serves fails at boot with the list of the wired ones, because the configuration tree cannot know
     * that list. A grant that spends a refresh token is worth nothing without one that issues it, so a
     * registration that names the first and none of the second is refused here too, where the two lists
     * meet; which grants those are, the wired grants say themselves and this reads nowhere else.
     *
     * @param array<string, mixed> $definition
     *
     * @throws InvalidArgumentException
     *
     * @return list<GrantTypeName>
     */
    private static function grantTypes(string $clientId, array $definition, ServedGrantsInterface $grants): array
    {
        $served = $grants->servedGrantTypes();
        $registered = [];
        foreach (self::stringList($clientId, 'grant_types', $definition['grant_types'] ?? self::DEFAULT_GRANT_TYPES) as $name) {
            $grantType = array_find($served, static fn (GrantTypeName $wired): bool => $wired->value === $name);
            if ($grantType === null) {
                throw self::oneOf($clientId, 'grant_types', GrantNames::of($served));
            }
            $registered[] = $grantType;
        }

        $isRegistered = static fn (GrantTypeName $grantType): bool => array_any(
            $registered,
            static fn (GrantTypeName $one): bool => $one->equals($grantType),
        );
        $spends = array_find($grants->spendingRefreshTokens(), $isRegistered);
        if ($spends !== null && ! array_any($grants->issuingRefreshTokens(), $isRegistered)) {
            throw new InvalidArgumentException(sprintf(
                'The client "%s" cannot spend with "%s" a refresh token it has no way to obtain: register it for one of: %s.',
                $clientId,
                $spends->value,
                implode(', ', GrantNames::of($grants->issuingRefreshTokens())),
            ));
        }

        return $registered;
    }

    /**
     * What names the client in the certificate it presents (RFC 8705 §2.1.2): one of the five keys, and
     * one only. A distinguished name is written back by the reader that will read the one of the
     * certificate, so that the registration is kept in the form the comparison will be made in and a
     * name that is not a distinguished name fails at boot rather than at the first request.
     *
     * @param array<string, mixed> $definition
     */
    private static function certificateIdentity(string $clientId, array $definition, CertificateReaderInterface $certificates): ?CertificateIdentityInterface
    {
        $registration = [];
        foreach (CertificateIdentities::NAMES as $key) {
            $registration[$key] = self::text($clientId, $key, $definition);
        }
        $subjectDn = $registration[CertificateIdentities::SUBJECT_DN];
        if ($subjectDn !== null) {
            try {
                $registration[CertificateIdentities::SUBJECT_DN] = $certificates->distinguishedName($subjectDn);
            } catch (UnreadableCertificateException $exception) {
                throw new InvalidArgumentException(
                    sprintf('The %s option of the client "%s" must be a distinguished name of RFC 4514.', CertificateIdentities::SUBJECT_DN, $clientId),
                    0,
                    $exception,
                );
            }
        }

        return CertificateIdentities::fromRegistration($registration);
    }

    /**
     * What the client registered in "request_object_signing_alg" (OIDC Registration §2), among the
     * algorithms the provider is wired with, plus the one value that is not an algorithm: "none", the
     * named exception of decision 0006, which is registered here and nowhere else. A client that
     * registers nothing has its request objects read under any algorithm the provider verifies, and
     * never unsigned.
     *
     * @param array<string, mixed> $definition
     */
    private static function requestObjectSigning(string $clientId, array $definition, SignatureAlgorithmsInterface $algorithms): RequestObjectSigningInterface
    {
        $name = self::text($clientId, 'request_object_signing_alg', $definition);
        if ($name === null) {
            return new AnyRegisteredAlgorithm();
        }
        if ($name === UnsignedRequestObjects::ALGORITHM) {
            return new UnsignedRequestObjects();
        }
        try {
            return new OneRegisteredAlgorithm($algorithms->named($name));
        } catch (UnsupportedAlgorithmException $exception) {
            throw new InvalidArgumentException(
                sprintf(
                    'The request_object_signing_alg option of the client "%s" must be "%s" or one of: %s.',
                    $clientId,
                    UnsignedRequestObjects::ALGORITHM,
                    implode(', ', AlgorithmNames::of($algorithms->all())),
                ),
                0,
                $exception,
            );
        }
    }

    /**
     * The JWK Set a client publishes inline (RFC 7591 §2), read as the document it is.
     *
     * @param array<string, mixed> $definition
     */
    private static function jwks(string $clientId, array $definition): ?ClientJwks
    {
        $jwks = $definition['jwks'] ?? null;
        if ($jwks === null) {
            return null;
        }
        if (! is_array($jwks)) {
            throw new InvalidArgumentException(sprintf('The jwks option of the client "%s" must be a JWK Set (RFC 7517 section 5).', $clientId));
        }

        return ClientJwks::fromDocument($jwks);
    }

    /**
     * A URI the provider calls or loads: where a logout token goes (Back-Channel Logout 1.0 §2.2), what
     * the logout page frames (Front-Channel Logout 1.0 §3), where the keys of the client are read back
     * from (RFC 7591 §2). Read and validated as every other URI a client registers.
     *
     * @param array<string, mixed> $definition
     */
    private static function clientUri(string $clientId, string $key, array $definition): ?ClientUri
    {
        $uri = self::text($clientId, $key, $definition);

        return $uri === null ? null : new ClientUri($uri);
    }

    /**
     * An option a client registers as text, read once for every one of them, so that a value of another
     * kind is refused the same way wherever it was written.
     *
     * @param array<string, mixed> $definition
     *
     * @return string|null null when the client registered none
     */
    private static function text(string $clientId, string $option, array $definition): ?string
    {
        $value = $definition[$option] ?? null;
        if ($value === null) {
            return null;
        }
        if (! is_string($value)) {
            throw new InvalidArgumentException(sprintf('The %s option of the client "%s" must be a string.', $option, $clientId));
        }

        return $value;
    }

    /**
     * A client registered a name the provider is not wired with. The configuration tree cannot know that
     * list, so the refusal carries it, and it is read from the wiring wherever the name came from.
     *
     * @param list<string> $wired
     */
    private static function oneOf(string $clientId, string $option, array $wired, ?UnsupportedAlgorithmException $previous = null): InvalidArgumentException
    {
        return new InvalidArgumentException(
            sprintf('The %s option of the client "%s" must be one of: %s.', $option, $clientId, implode(', ', $wired)),
            0,
            $previous,
        );
    }

    /**
     * @param array<string, mixed> $definition
     */
    private static function flag(string $clientId, string $key, array $definition, bool $default = false): bool
    {
        $value = $definition[$key] ?? $default;
        if (! is_bool($value)) {
            throw new InvalidArgumentException(sprintf('The %s option of the client "%s" must be a boolean.', $key, $clientId));
        }

        return $value;
    }

    /**
     * @return list<string>
     */
    private static function stringList(string $clientId, string $key, mixed $value): array
    {
        $refusal = new InvalidArgumentException(sprintf('The %s option of the client "%s" must be a list of strings.', $key, $clientId));
        if (! is_array($value)) {
            throw $refusal;
        }
        $list = [];
        foreach ($value as $item) {
            if (! is_string($item)) {
                throw $refusal;
            }
            $list[] = $item;
        }

        return $list;
    }
}

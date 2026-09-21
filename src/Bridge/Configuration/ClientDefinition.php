<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\Configuration;

use function array_column;
use function array_diff;
use function array_keys;
use function array_map;
use BackedEnum;
use Heidi\Core\Domain\Key\SignatureAlgorithmInterface;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\UnsupportedAlgorithmException;
use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Oidc\Application\Client\Method\SecretKeepingMethodInterface;
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Domain\Client\Certificate\CertificateIdentities;
use Heidi\Oidc\Domain\Client\Certificate\CertificateIdentityInterface;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Heidi\Oidc\Domain\Client\ClientJwks;
use Heidi\Oidc\Domain\Client\ClientSecretInterface;
use Heidi\Oidc\Domain\Client\ClientUri;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
use Heidi\Oidc\Exception\UnreadableCertificateException;
use Heidi\Oidc\Port\CertificateReaderInterface;
use Heidi\Oidc\Port\ClientAuthenticationMethodsInterface;
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
        'requires_pkce',
        'access_token_format',
        'backchannel_logout_uri',
        'backchannel_logout_session_required',
        'frontchannel_logout_uri',
        'frontchannel_logout_session_required',
        'jwks',
        'jwks_uri',
        ...CertificateIdentities::NAMES,
    ];

    /**
     * @param list<RedirectUri> $redirectUris
     * @param list<RedirectUri> $postLogoutRedirectUris
     * @param list<GrantType> $grantTypes
     * @param list<Scope> $allowedScopes
     */
    private function __construct(
        public string $clientId,
        public string $name,
        #[SensitiveParameter]
        private ?string $secret,
        public ClientAuthenticationMethodInterface $authenticationMethod,
        public array $redirectUris,
        public array $postLogoutRedirectUris,
        public array $grantTypes,
        public array $allowedScopes,
        public bool $requiresConsent,
        public SignatureAlgorithmInterface $idTokenSignedResponseAlg,
        public bool $requiresPkce,
        public AccessTokenFormat $accessTokenFormat,
        public ?ClientUri $backChannelLogoutUri,
        public bool $backChannelLogoutSessionRequired,
        public ?ClientUri $frontChannelLogoutUri,
        public bool $frontChannelLogoutSessionRequired,
        public ?ClientJwks $jwks,
        public ?ClientUri $jwksUri,
        public ?CertificateIdentityInterface $certificateIdentity,
    ) {
    }

    /**
     * @param array<string, mixed> $definition the keys of architecture §5.1, in snake_case
     * @param SignatureAlgorithmsInterface $algorithms what the provider signs with: a client registers one of those names, or none and takes the default
     * @param ClientAuthenticationMethodsInterface $methods what the provider authenticates clients with: a client registers one of those names
     * @param CertificateReaderInterface $certificates what writes a registered distinguished name the way it will be read out of a certificate (RFC 8705 §2.1.2)
     */
    public static function fromArray(string $clientId, array $definition, SignatureAlgorithmsInterface $algorithms, ClientAuthenticationMethodsInterface $methods, CertificateReaderInterface $certificates): self
    {
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
                throw new InvalidArgumentException(sprintf('The secret of the client "%s" must be at least 32 visible ASCII characters long; generate it, do not choose it.', $clientId));
            }
        }

        $method = self::method($clientId, $definition['token_endpoint_auth_method'] ?? null, $methods);

        $requiresConsent = $definition['requires_consent'] ?? true;
        if (! is_bool($requiresConsent)) {
            throw new InvalidArgumentException(sprintf('The requires_consent option of the client "%s" must be a boolean.', $clientId));
        }

        $requiresPkce = $definition['requires_pkce'] ?? true;
        if (! is_bool($requiresPkce)) {
            throw new InvalidArgumentException(sprintf('The requires_pkce option of the client "%s" must be a boolean.', $clientId));
        }

        $name = $definition['name'] ?? $clientId;
        if (! is_string($name)) {
            throw new InvalidArgumentException(sprintf('The name of the client "%s" must be a string.', $clientId));
        }

        $redirectUris = array_map(static fn (string $uri): RedirectUri => new RedirectUri($uri), self::stringList($clientId, 'redirect_uris', $definition['redirect_uris'] ?? []));
        $postLogoutRedirectUris = array_map(static fn (string $uri): RedirectUri => new RedirectUri($uri), self::stringList($clientId, 'post_logout_redirect_uris', $definition['post_logout_redirect_uris'] ?? []));
        $grantTypes = array_map(static fn (string $grant): GrantType => self::enumCase($clientId, 'grant_types', $grant, GrantType::class), self::stringList($clientId, 'grant_types', $definition['grant_types'] ?? [GrantType::AuthorizationCode->value, GrantType::RefreshToken->value]));
        $allowedScopes = array_map(static fn (string $scope): Scope => new Scope($scope), self::stringList($clientId, 'allowed_scopes', $definition['allowed_scopes'] ?? ['openid', 'profile', 'email']));
        $signedResponseAlg = $definition['id_token_signed_response_alg'] ?? null;
        if ($signedResponseAlg !== null && ! is_string($signedResponseAlg)) {
            throw new InvalidArgumentException(sprintf('The id_token_signed_response_alg option of the client "%s" must be a string.', $clientId));
        }
        try {
            $algorithm = $signedResponseAlg === null ? $algorithms->defaultAlgorithm() : $algorithms->named($signedResponseAlg);
        } catch (UnsupportedAlgorithmException $exception) {
            throw new InvalidArgumentException(sprintf('The id_token_signed_response_alg option of the client "%s" must be one of: %s.', $clientId, implode(', ', array_map(static fn (SignatureAlgorithmInterface $wired): string => $wired->name(), $algorithms->all()))), 0, $exception);
        }

        $accessTokenFormat = self::enumCase($clientId, 'access_token_format', $definition['access_token_format'] ?? AccessTokenFormat::Jwt->value, AccessTokenFormat::class);

        $jwks = self::jwks($clientId, $definition);
        $jwksUri = self::clientUri($clientId, 'jwks_uri', $definition);

        $backChannelLogoutUri = self::clientUri($clientId, 'backchannel_logout_uri', $definition);
        $backChannelLogoutSessionRequired = self::flag($clientId, 'backchannel_logout_session_required', $definition);
        $frontChannelLogoutUri = self::clientUri($clientId, 'frontchannel_logout_uri', $definition);
        $frontChannelLogoutSessionRequired = self::flag($clientId, 'frontchannel_logout_session_required', $definition);

        $certificateIdentity = self::certificateIdentity($clientId, $definition, $certificates);

        Client::assertConsistent($clientId, $name, $method, $secret !== null, $redirectUris, $grantTypes, $allowedScopes, $requiresPkce, $backChannelLogoutUri !== null, $backChannelLogoutSessionRequired, $frontChannelLogoutUri !== null, $frontChannelLogoutSessionRequired, $jwks !== null, $jwksUri !== null, $certificateIdentity !== null);

        return new self($clientId, $name, $secret, $method, $redirectUris, $postLogoutRedirectUris, $grantTypes, $allowedScopes, $requiresConsent, $algorithm, $requiresPkce, $accessTokenFormat, $backChannelLogoutUri, $backChannelLogoutSessionRequired, $frontChannelLogoutUri, $frontChannelLogoutSessionRequired, $jwks, $jwksUri, $certificateIdentity);
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
        $method = $this->authenticationMethod;
        if ($this->secret === null || ! $method instanceof SecretKeepingMethodInterface) {
            throw new LogicException(sprintf('The client "%s" registers no secret to keep.', $this->clientId));
        }

        return $method->keep($this->secret, $hasher);
    }

    public function toClient(Tenant $tenant, ?ClientSecretInterface $secret): Client
    {
        return new Client(
            $tenant,
            $this->clientId,
            $this->name,
            $this->authenticationMethod,
            $secret,
            $this->redirectUris,
            $this->postLogoutRedirectUris,
            $this->grantTypes,
            $this->allowedScopes,
            $this->requiresConsent,
            $this->idTokenSignedResponseAlg,
            $this->requiresPkce,
            $this->accessTokenFormat,
            $this->backChannelLogoutUri,
            $this->backChannelLogoutSessionRequired,
            $this->frontChannelLogoutUri,
            $this->frontChannelLogoutSessionRequired,
            $this->jwks,
            $this->jwksUri,
            $this->certificateIdentity,
        );
    }

    /**
     * The method the client registers, among those the provider is wired with (issue #98): a name
     * nothing authenticates with fails at boot with the list of the wired ones, because the
     * configuration tree cannot know that list.
     */
    private static function method(string $clientId, mixed $name, ClientAuthenticationMethodsInterface $methods): ClientAuthenticationMethodInterface
    {
        $wired = $methods->clientAuthenticationMethods();
        if ($name === null) {
            return $wired[0];
        }
        if (! is_string($name)) {
            throw new InvalidArgumentException(sprintf('The token_endpoint_auth_method option of the client "%s" must be a string.', $clientId));
        }
        foreach ($wired as $method) {
            if ($method->name() === $name) {
                return $method;
            }
        }

        throw new InvalidArgumentException(sprintf('The token_endpoint_auth_method option of the client "%s" must be one of: %s.', $clientId, implode(', ', array_map(static fn (ClientAuthenticationMethodInterface $method): string => $method->name(), $wired))));
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
            $value = $definition[$key] ?? null;
            if ($value !== null && ! is_string($value)) {
                throw new InvalidArgumentException(sprintf('The %s option of the client "%s" must be a string.', $key, $clientId));
            }
            $registration[$key] = $value;
        }
        $subjectDn = $registration[CertificateIdentities::SUBJECT_DN];
        if ($subjectDn !== null) {
            try {
                $registration[CertificateIdentities::SUBJECT_DN] = $certificates->distinguishedName($subjectDn);
            } catch (UnreadableCertificateException $exception) {
                throw new InvalidArgumentException(sprintf('The %s option of the client "%s" must be a distinguished name of RFC 4514.', CertificateIdentities::SUBJECT_DN, $clientId), 0, $exception);
            }
        }

        return CertificateIdentities::fromRegistration($registration);
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
        $uri = $definition[$key] ?? null;
        if ($uri === null) {
            return null;
        }
        if (! is_string($uri)) {
            throw new InvalidArgumentException(sprintf('The %s option of the client "%s" must be a string.', $key, $clientId));
        }

        return new ClientUri($uri);
    }

    /**
     * @param array<string, mixed> $definition
     */
    private static function flag(string $clientId, string $key, array $definition): bool
    {
        $value = $definition[$key] ?? false;
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
        if (! is_array($value)) {
            throw new InvalidArgumentException(sprintf('The %s option of the client "%s" must be a list of strings.', $key, $clientId));
        }
        $list = [];
        foreach ($value as $item) {
            if (! is_string($item)) {
                throw new InvalidArgumentException(sprintf('The %s option of the client "%s" must be a list of strings.', $key, $clientId));
            }
            $list[] = $item;
        }

        return $list;
    }

    /**
     * @template T of BackedEnum
     *
     * @param class-string<T> $enum
     *
     * @return T
     */
    private static function enumCase(string $clientId, string $key, mixed $value, string $enum): object
    {
        $case = is_string($value) ? $enum::tryFrom($value) : null;
        if ($case === null) {
            throw new InvalidArgumentException(sprintf('The %s option of the client "%s" must be one of: %s.', $key, $clientId, implode(', ', array_column($enum::cases(), 'value'))));
        }

        return $case;
    }
}

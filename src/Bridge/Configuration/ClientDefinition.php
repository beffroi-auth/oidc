<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\Configuration;

use function array_column;
use function array_diff;
use function array_keys;
use function array_map;
use BackedEnum;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
use function implode;
use function is_array;
use function is_bool;
use function is_string;
use function preg_match;
use SensitiveParameter;
use function sprintf;

/**
 * One client as the configuration declares it (architecture §5.1), read strictly: every key is known,
 * every value has the type the key expects, nothing is cast. The secret stays in clear here, as the
 * configuration holds it, and is hashed when the client is built.
 */
final readonly class ClientDefinition
{
    /**
     * RFC 6749 appendix A.2: a client secret is made of visible ASCII characters (VSCHAR). Shorter than
     * 32 of them, it is not the high-entropy secret RFC 6819 §5.1.4.2.2 asks for; the configuration is
     * refused rather than the secret being weak.
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
        public TokenEndpointAuthMethod $tokenEndpointAuthMethod,
        public array $redirectUris,
        public array $postLogoutRedirectUris,
        public array $grantTypes,
        public array $allowedScopes,
        public bool $requiresConsent,
        public SignatureAlgorithm $idTokenSignedResponseAlg,
        public bool $requiresPkce,
        public AccessTokenFormat $accessTokenFormat,
    ) {
    }

    /**
     * @param array<string, mixed> $definition the keys of architecture §5.1, in snake_case
     */
    public static function fromArray(string $clientId, array $definition): self
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

        $method = self::enumCase($clientId, 'token_endpoint_auth_method', $definition['token_endpoint_auth_method'] ?? TokenEndpointAuthMethod::ClientSecretBasic->value, TokenEndpointAuthMethod::class);

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
        $algorithm = self::enumCase($clientId, 'id_token_signed_response_alg', $definition['id_token_signed_response_alg'] ?? SignatureAlgorithm::RS256->value, SignatureAlgorithm::class);

        $accessTokenFormat = self::enumCase($clientId, 'access_token_format', $definition['access_token_format'] ?? AccessTokenFormat::Jwt->value, AccessTokenFormat::class);
        Client::assertConsistent($clientId, $name, $method, $secret !== null, $redirectUris, $grantTypes, $allowedScopes, $requiresPkce);

        return new self($clientId, $name, $secret, $method, $redirectUris, $postLogoutRedirectUris, $grantTypes, $allowedScopes, $requiresConsent, $algorithm, $requiresPkce, $accessTokenFormat);
    }

    public function hasSecret(): bool
    {
        return $this->secret !== null;
    }

    /**
     * Hashes the secret: as costly as hashing a password, by design, so call it once per process and keep
     * the hash.
     *
     * @throws LogicException for a public client, which has no secret; ask hasSecret() first
     */
    public function hashSecret(PasswordHasherInterface $hasher): PasswordHash
    {
        if ($this->secret === null) {
            throw new LogicException(sprintf('The client "%s" is public and has no secret to hash.', $this->clientId));
        }

        return $hasher->hash($this->secret);
    }

    /**
     * @param PasswordHash|null $secretHash the hash of the secret, see hashSecret(); null for a public client
     */
    public function toClient(Tenant $tenant, ?PasswordHash $secretHash): Client
    {
        return new Client(
            $tenant,
            $this->clientId,
            $this->name,
            $this->tokenEndpointAuthMethod,
            $secretHash,
            $this->redirectUris,
            $this->postLogoutRedirectUris,
            $this->grantTypes,
            $this->allowedScopes,
            $this->requiresConsent,
            $this->idTokenSignedResponseAlg,
            $this->requiresPkce,
            $this->accessTokenFormat,
        );
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

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Discovery;

use function array_filter;
use function array_map;
use function array_values;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Domain\Authorization\ResponseMode;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function in_array;
use function sprintf;
use function strlen;
use function substr;

/**
 * The metadata of a tenant (OIDC Discovery §3, RFC 8414 §2): one document, two well-known locations. It
 * says what the provider does and nothing it does not (decision 0006); what is listed comes from the
 * enumerations of the module, so that the document and the endpoints cannot disagree.
 */
final readonly class ProviderMetadata
{
    public const string CONTENT_TYPE = 'application/json';

    public const string OPENID_CONFIGURATION_PATH = '/.well-known/openid-configuration';

    public const string AUTHORIZATION_SERVER_METADATA_PATH = '/.well-known/oauth-authorization-server';

    /**
     * @var non-empty-list<Scope> "openid" first, no duplicate
     */
    public array $scopesSupported;

    /**
     * @var non-empty-list<string> "sub" first, no duplicate
     */
    public array $claimsSupported;

    /**
     * @var array<string, string>
     */
    public array $headers;

    /**
     * @param list<Scope> $scopesSupported "openid" added if missing
     * @param list<string> $claimsSupported "sub" added if missing
     * @param int $maxAge how long a client may cache the document, in seconds
     */
    public function __construct(
        public Issuer $issuer,
        public ProviderEndpoints $endpoints,
        array $scopesSupported,
        array $claimsSupported,
        public int $maxAge,
    ) {
        if ($maxAge < 0) {
            throw new InvalidArgumentException('The cache lifetime of the provider metadata is a number of seconds.');
        }
        $scopes = [Scope::openid()];
        foreach ($scopesSupported as $scope) {
            if (! in_array($scope->value, array_map(static fn (Scope $known): string => $known->value, $scopes), true)) {
                $scopes[] = $scope;
            }
        }
        $claims = ['sub'];
        foreach ($claimsSupported as $claim) {
            if ($claim === '') {
                throw new InvalidArgumentException('A supported claim has a name.');
            }
            if (! in_array($claim, $claims, true)) {
                $claims[] = $claim;
            }
        }
        $this->scopesSupported = $scopes;
        $this->claimsSupported = $claims;
        $this->headers = [
            'Cache-Control' => sprintf('public, max-age=%d', $maxAge),
        ];
    }

    /**
     * OIDC Discovery §4.1: appended to the issuer, path included.
     */
    public function openIdConfigurationUrl(): string
    {
        return $this->issuer->value . self::OPENID_CONFIGURATION_PATH;
    }

    /**
     * RFC 8414 §3: inserted between the host and the path of the issuer.
     */
    public function authorizationServerMetadataUrl(): string
    {
        $origin = substr($this->issuer->value, 0, strlen($this->issuer->value) - strlen($this->issuer->path));

        return $origin . self::AUTHORIZATION_SERVER_METADATA_PATH . $this->issuer->path;
    }

    /**
     * In the order of OIDC Discovery §3, then RFC 8414 §2, RFC 9701 §6, RFC 9207 §3, RP-Initiated Logout §2.1.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'issuer' => $this->issuer->value,
            'authorization_endpoint' => $this->endpoints->authorization,
            'token_endpoint' => $this->endpoints->token,
            'userinfo_endpoint' => $this->endpoints->userinfo,
            'jwks_uri' => $this->endpoints->jwks,
            'scopes_supported' => array_map(static fn (Scope $scope): string => $scope->value, $this->scopesSupported),
            'response_types_supported' => ['code'],
            'response_modes_supported' => self::values(ResponseMode::cases()),
            'grant_types_supported' => self::values(GrantType::cases()),
            'acr_values_supported' => AuthenticationContextClass::supported(),
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => self::values(SignatureAlgorithm::cases()),
            'token_endpoint_auth_methods_supported' => self::values(TokenEndpointAuthMethod::cases()),
            'claims_supported' => $this->claimsSupported,
            'claims_parameter_supported' => true,
            'request_parameter_supported' => false,
            'request_uri_parameter_supported' => false,
            'code_challenge_methods_supported' => self::values(CodeChallengeMethod::cases()),
            'revocation_endpoint' => $this->endpoints->revocation,
            'revocation_endpoint_auth_methods_supported' => self::values(TokenEndpointAuthMethod::cases()),
            'introspection_endpoint' => $this->endpoints->introspection,
            'introspection_endpoint_auth_methods_supported' => self::values(self::secretMethods()),
            'introspection_signing_alg_values_supported' => self::values(SignatureAlgorithm::cases()),
            'authorization_response_iss_parameter_supported' => true,
            'end_session_endpoint' => $this->endpoints->endSession,
        ];
    }

    public function toJson(): string
    {
        return JwtPayload::encode($this->toArray());
    }

    /**
     * RFC 7662 §2.1: the methods that prove a secret.
     *
     * @return list<TokenEndpointAuthMethod>
     */
    private static function secretMethods(): array
    {
        return array_values(array_filter(TokenEndpointAuthMethod::cases(), static fn (TokenEndpointAuthMethod $method): bool => $method->usesSecret()));
    }

    /**
     * @param list<ResponseMode|GrantType|SignatureAlgorithm|TokenEndpointAuthMethod|CodeChallengeMethod> $cases
     *
     * @return list<string>
     */
    private static function values(array $cases): array
    {
        return array_map(static fn ($case): string => $case->value, $cases);
    }
}

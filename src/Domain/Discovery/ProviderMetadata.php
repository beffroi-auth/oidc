<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Discovery;

use function array_filter;
use function array_map;
use function array_unique;
use function array_values;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Domain\Authorization\ResponseMode;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function in_array;
use const SORT_REGULAR;
use function sprintf;
use function strlen;
use function substr;

/**
 * The metadata of a tenant (OIDC Discovery §3, RFC 8414 §2): one document, two well-known locations. It
 * says what the provider does and nothing it does not (decision 0006): the grant types are the grants
 * wired into the token endpoint, the response modes the ways of answering wired into the authorization
 * endpoint, the client authentication methods those the client authenticator implements and the "acr"
 * values the classes of the tenant's policy its logins can prove, given by the discovery handler, never
 * read from an enumeration, so that the document and the endpoints cannot disagree; the rest is fixed by
 * the module.
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
     * @var non-empty-list<ResponseMode> no duplicate
     */
    public array $responseModesSupported;

    /**
     * @var non-empty-list<GrantType> no duplicate
     */
    public array $grantTypesSupported;

    /**
     * @var non-empty-list<TokenEndpointAuthMethod> no duplicate
     */
    public array $tokenEndpointAuthMethodsSupported;

    /**
     * @var non-empty-list<string> no duplicate
     */
    public array $acrValuesSupported;

    /**
     * @var array<string, string>
     */
    public array $headers;

    /**
     * @param list<Scope> $scopesSupported "openid" added if missing
     * @param list<string> $claimsSupported "sub" added if missing
     * @param list<ResponseMode> $responseModesSupported the modes the authorization endpoint answers in, at least one
     * @param list<GrantType> $grantTypesSupported the grants the token endpoint serves, at least one
     * @param list<TokenEndpointAuthMethod> $tokenEndpointAuthMethodsSupported the methods the token endpoint takes, at least one
     * @param list<string> $acrValuesSupported the classes of the policy of the tenant a login can prove, at least one
     * @param int $maxAge how long a client may cache the document, in seconds
     */
    public function __construct(
        public Issuer $issuer,
        public ProviderEndpoints $endpoints,
        array $scopesSupported,
        array $claimsSupported,
        array $responseModesSupported,
        array $grantTypesSupported,
        array $tokenEndpointAuthMethodsSupported,
        array $acrValuesSupported,
        public int $maxAge,
    ) {
        if ($maxAge < 0) {
            throw new InvalidArgumentException('The cache lifetime of the provider metadata is a number of seconds.');
        }
        $responseModes = array_values(array_unique($responseModesSupported, SORT_REGULAR));
        if ($responseModes === []) {
            throw new InvalidArgumentException('An authorization endpoint answers in at least one response mode (RFC 8414 section 2).');
        }
        $grantTypes = array_values(array_unique($grantTypesSupported, SORT_REGULAR));
        if ($grantTypes === []) {
            throw new InvalidArgumentException('A provider serves at least one grant type (RFC 8414 section 2).');
        }
        $methods = array_values(array_unique($tokenEndpointAuthMethodsSupported, SORT_REGULAR));
        if ($methods === []) {
            throw new InvalidArgumentException('A token endpoint takes at least one client authentication method (RFC 8414 section 2).');
        }
        $acrValues = array_values(array_unique($acrValuesSupported));
        if ($acrValues === []) {
            throw new InvalidArgumentException('A provider asserts at least one authentication context class (OIDC Discovery section 3).');
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
        $this->responseModesSupported = $responseModes;
        $this->scopesSupported = $scopes;
        $this->claimsSupported = $claims;
        $this->grantTypesSupported = $grantTypes;
        $this->tokenEndpointAuthMethodsSupported = $methods;
        $this->acrValuesSupported = $acrValues;
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
            'response_modes_supported' => self::values($this->responseModesSupported),
            'grant_types_supported' => self::values($this->grantTypesSupported),
            'acr_values_supported' => $this->acrValuesSupported,
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => self::values(SignatureAlgorithm::cases()),
            'token_endpoint_auth_methods_supported' => self::values($this->tokenEndpointAuthMethodsSupported),
            'claims_supported' => $this->claimsSupported,
            'claims_parameter_supported' => true,
            'request_parameter_supported' => false,
            'request_uri_parameter_supported' => false,
            'code_challenge_methods_supported' => self::values(CodeChallengeMethod::cases()),
            'revocation_endpoint' => $this->endpoints->revocation,
            'revocation_endpoint_auth_methods_supported' => self::values($this->tokenEndpointAuthMethodsSupported),
            'introspection_endpoint' => $this->endpoints->introspection,
            'introspection_endpoint_auth_methods_supported' => self::values($this->secretMethods()),
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
     * RFC 7662 §2.1: the methods that prove a secret, among those the token endpoint takes.
     *
     * @return list<TokenEndpointAuthMethod>
     */
    private function secretMethods(): array
    {
        return array_values(array_filter($this->tokenEndpointAuthMethodsSupported, static fn (TokenEndpointAuthMethod $method): bool => $method->usesSecret()));
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

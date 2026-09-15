<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Discovery;

use function array_map;
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
use function sprintf;
use function strlen;
use function substr;

/**
 * The metadata of a tenant as an OpenID Provider (OIDC Discovery §3) and as an OAuth 2.0 authorization
 * server (RFC 8414 §2): one document for both, since the members of the second are a subset of the first,
 * served at the two well-known locations the specifications derive from the issuer. It says what the
 * provider does, and nothing the provider does not: one response type, one response mode, one code
 * challenge method, no request object, no "request_uri", so that a client reading it cannot ask for what
 * decision 0006 refuses. What is listed comes from the enumerations of the module wherever one exists, so
 * that the document and the endpoints cannot disagree.
 *
 * "authorization_response_iss_parameter_supported" (RFC 9207 §3) is what makes Symfony's oidc_login
 * require "iss" on every callback: announcing it is how the provider gets the mix-up defence enforced on
 * the client side too.
 */
final readonly class ProviderMetadata
{
    public const string CONTENT_TYPE = 'application/json';

    public const string OPENID_CONFIGURATION_PATH = '/.well-known/openid-configuration';

    public const string AUTHORIZATION_SERVER_METADATA_PATH = '/.well-known/oauth-authorization-server';

    /**
     * @var non-empty-list<Scope> "openid" first (OIDC Discovery §3: the server MUST support it), no duplicate
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
     * @param list<Scope> $scopesSupported the scopes the provider serves, "openid" added if missing
     * @param list<string> $claimsSupported the claim names the provider may supply values for, "sub" added if missing
     * @param int $maxAge how long a client may cache the document, in seconds: the document changes when the deployment does
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
     * OIDC Discovery §4.1: the well-known path is appended to the issuer, path included.
     */
    public function openIdConfigurationUrl(): string
    {
        return $this->issuer->value . self::OPENID_CONFIGURATION_PATH;
    }

    /**
     * RFC 8414 §3: the well-known path is inserted between the host and the path of the issuer, so that
     * "https://as.example/tenant1" is served at "https://as.example/.well-known/oauth-authorization-server/tenant1".
     * The two locations only differ when the issuer carries a path.
     */
    public function authorizationServerMetadataUrl(): string
    {
        $origin = substr($this->issuer->value, 0, strlen($this->issuer->value) - strlen($this->issuer->path));

        return $origin . self::AUTHORIZATION_SERVER_METADATA_PATH . $this->issuer->path;
    }

    /**
     * The document, members in the order OIDC Discovery §3 lists them, then those of RFC 8414 §2 and
     * RFC 9207 §3 it does not have, then the end session endpoint (RP-Initiated Logout §2.1).
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
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => self::values(SignatureAlgorithm::cases()),
            'token_endpoint_auth_methods_supported' => self::values(TokenEndpointAuthMethod::cases()),
            'claims_supported' => $this->claimsSupported,
            'claims_parameter_supported' => true,
            'request_parameter_supported' => false,
            'request_uri_parameter_supported' => false,
            'code_challenge_methods_supported' => self::values(CodeChallengeMethod::cases()),
            'authorization_response_iss_parameter_supported' => true,
            'end_session_endpoint' => $this->endpoints->endSession,
        ];
    }

    /**
     * @return string the JSON object, UTF-8, booleans as they are
     */
    public function toJson(): string
    {
        return JwtPayload::encode($this->toArray());
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

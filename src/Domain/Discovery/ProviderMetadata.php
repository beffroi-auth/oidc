<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Discovery;

use function array_filter;
use function array_map;
use function array_merge;
use function array_unique;
use function array_values;
use Heidi\Core\Domain\Key\SignatureAlgorithmInterface;
use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Domain\Authorization\ResponseMode;
use Heidi\Oidc\Domain\Client\AssertionMethodInterface;
use Heidi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\EndSession\LogoutChannel;
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
 * values the classes of the tenant's policy its logins can prove, the signing algorithms those the
 * provider is wired with and the logout channels the ways of telling a client a session ended that are
 * wired, given by the discovery handler, never read from an enumeration, so that the document and the
 * endpoints cannot disagree; the rest is fixed by the module.
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
     * @var non-empty-list<ClientAuthenticationMethodInterface> no duplicate
     */
    public array $clientAuthenticationMethodsSupported;

    /**
     * @var non-empty-list<string> no duplicate
     */
    public array $acrValuesSupported;

    /**
     * @var non-empty-list<SignatureAlgorithmInterface> no duplicate
     */
    public array $signingAlgorithmsSupported;

    /**
     * @var list<LogoutChannel> no duplicate
     */
    public array $logoutChannelsSupported;

    /**
     * @var array<string, string>
     */
    public array $headers;

    /**
     * @param list<Scope> $scopesSupported "openid" added if missing
     * @param list<string> $claimsSupported "sub" added if missing
     * @param list<ResponseMode> $responseModesSupported the modes the authorization endpoint answers in, at least one
     * @param list<GrantType> $grantTypesSupported the grants the token endpoint serves, at least one
     * @param list<ClientAuthenticationMethodInterface> $clientAuthenticationMethodsSupported the methods the endpoints that authenticate a client take, at least one
     * @param list<string> $acrValuesSupported the classes of the policy of the tenant a login can prove, at least one
     * @param list<SignatureAlgorithmInterface> $signingAlgorithmsSupported the algorithms the provider signs its JWS with, at least one
     * @param list<LogoutChannel> $logoutChannelsSupported the ways of telling a client a session ended the integration serves, none of them if it serves none
     * @param int $maxAge how long a client may cache the document, in seconds
     */
    public function __construct(
        public Issuer $issuer,
        public ProviderEndpoints $endpoints,
        array $scopesSupported,
        array $claimsSupported,
        array $responseModesSupported,
        array $grantTypesSupported,
        array $clientAuthenticationMethodsSupported,
        array $acrValuesSupported,
        array $signingAlgorithmsSupported,
        array $logoutChannelsSupported,
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
        $methods = [];
        foreach ($clientAuthenticationMethodsSupported as $method) {
            if (! in_array($method->name(), array_map(static fn (ClientAuthenticationMethodInterface $kept): string => $kept->name(), $methods), true)) {
                $methods[] = $method;
            }
        }
        if ($methods === []) {
            throw new InvalidArgumentException('A token endpoint takes at least one client authentication method (RFC 8414 section 2).');
        }
        $acrValues = array_values(array_unique($acrValuesSupported));
        if ($acrValues === []) {
            throw new InvalidArgumentException('A provider asserts at least one authentication context class (OIDC Discovery section 3).');
        }
        $algorithms = array_values(array_unique($signingAlgorithmsSupported, SORT_REGULAR));
        if ($algorithms === []) {
            throw new InvalidArgumentException('A provider signs its JWS with at least one algorithm (OIDC Discovery section 3).');
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
        $this->clientAuthenticationMethodsSupported = $methods;
        $this->acrValuesSupported = $acrValues;
        $this->signingAlgorithmsSupported = $algorithms;
        $this->logoutChannelsSupported = array_values(array_unique($logoutChannelsSupported, SORT_REGULAR));
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
            'id_token_signing_alg_values_supported' => $this->algorithmNames(),
            'token_endpoint_auth_methods_supported' => $this->methodNames($this->clientAuthenticationMethodsSupported),
            'token_endpoint_auth_signing_alg_values_supported' => $this->assertionSigningAlgorithms($this->clientAuthenticationMethodsSupported),
            'claims_supported' => $this->claimsSupported,
            'claims_parameter_supported' => true,
            'request_parameter_supported' => false,
            'request_uri_parameter_supported' => false,
            'code_challenge_methods_supported' => self::values(CodeChallengeMethod::cases()),
            'revocation_endpoint' => $this->endpoints->revocation,
            'revocation_endpoint_auth_methods_supported' => $this->methodNames($this->clientAuthenticationMethodsSupported),
            'revocation_endpoint_auth_signing_alg_values_supported' => $this->assertionSigningAlgorithms($this->clientAuthenticationMethodsSupported),
            'introspection_endpoint' => $this->endpoints->introspection,
            'introspection_endpoint_auth_methods_supported' => $this->methodNames($this->authenticatingMethods()),
            'introspection_endpoint_auth_signing_alg_values_supported' => $this->assertionSigningAlgorithms($this->authenticatingMethods()),
            'introspection_signing_alg_values_supported' => $this->algorithmNames(),
            'authorization_response_iss_parameter_supported' => true,
            'end_session_endpoint' => $this->endpoints->endSession,
            // Back-Channel Logout 1.0 §3 and Front-Channel Logout 1.0 §3: a channel that is served
            // always carries the session, so what announces one announces the other
            'backchannel_logout_supported' => $this->serves(LogoutChannel::BackChannel),
            'backchannel_logout_session_supported' => $this->serves(LogoutChannel::BackChannel),
            'frontchannel_logout_supported' => $this->serves(LogoutChannel::FrontChannel),
            'frontchannel_logout_session_supported' => $this->serves(LogoutChannel::FrontChannel),
        ];
    }

    public function toJson(): string
    {
        return JwtPayload::encode($this->toArray());
    }

    /**
     * RFC 8414 §2 and OIDC Discovery §3: the "alg" of every algorithm the provider is wired with, in the
     * order they are wired.
     *
     * @return non-empty-list<string>
     */
    private function algorithmNames(): array
    {
        return array_map(static fn (SignatureAlgorithmInterface $algorithm): string => $algorithm->name(), $this->signingAlgorithmsSupported);
    }

    /**
     * Back-Channel Logout 1.0 §3, Front-Channel Logout 1.0 §3: a channel nothing serves is announced as
     * not served, never left out.
     */
    private function serves(LogoutChannel $channel): bool
    {
        return in_array($channel, $this->logoutChannelsSupported, true);
    }

    /**
     * RFC 7662 §2.1: the methods that authenticate the caller, among those the provider takes; a public
     * client has none and the introspection endpoint does not serve it.
     *
     * @return list<ClientAuthenticationMethodInterface>
     */
    private function authenticatingMethods(): array
    {
        return array_values(array_filter($this->clientAuthenticationMethodsSupported, static fn (ClientAuthenticationMethodInterface $method): bool => $method->authenticatesClient()));
    }

    /**
     * @param list<ClientAuthenticationMethodInterface> $methods
     *
     * @return list<string>
     */
    private function methodNames(array $methods): array
    {
        return array_map(static fn (ClientAuthenticationMethodInterface $method): string => $method->name(), $methods);
    }

    /**
     * OIDC Discovery §3 and RFC 8414 §2: the "alg" the assertions of the wired methods may be signed
     * with, each named once, in the order the methods are wired. A provider that takes no assertion
     * announces an empty list rather than a name it would refuse.
     *
     * @param list<ClientAuthenticationMethodInterface> $methods
     *
     * @return list<string>
     */
    private function assertionSigningAlgorithms(array $methods): array
    {
        $algorithms = [];
        foreach ($methods as $method) {
            if ($method instanceof AssertionMethodInterface) {
                $algorithms = array_merge($algorithms, $method->assertionSigningAlgorithms());
            }
        }

        return array_values(array_unique($algorithms));
    }

    /**
     * @param list<ResponseMode|GrantType|CodeChallengeMethod> $cases
     *
     * @return list<string>
     */
    private static function values(array $cases): array
    {
        return array_map(static fn ($case): string => $case->value, $cases);
    }
}

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Discovery;

use function array_any;
use function array_filter;
use function array_map;
use function array_merge;
use function array_unique;
use function array_values;
use Heidi\Core\Domain\Key\ContentEncryptionAlgorithmInterface;
use Heidi\Core\Domain\Key\KeyEncryptionAlgorithmInterface;
use Heidi\Core\Domain\Key\SignatureAlgorithmInterface;
use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Domain\Authorization\ResponseMode;
use Heidi\Oidc\Domain\Client\AssertionMethodInterface;
use Heidi\Oidc\Domain\Client\CertificateBindingMethodInterface;
use Heidi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Client\RequestObject\UnsignedRequestObjects;
use Heidi\Oidc\Domain\EndSession\LogoutChannel;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function in_array;
use const SORT_REGULAR;
use function sprintf;

/**
 * The metadata of a tenant (OIDC Discovery §3, RFC 8414 §2): one document, two well-known locations. It
 * says what the provider does and nothing it does not (decision 0006): the grant types are the grants
 * wired into the token endpoint, the response modes the ways of answering wired into the authorization
 * endpoint, the client authentication methods those the client authenticator implements and the "acr"
 * values the classes of the tenant's policy its logins can prove, the signing algorithms those the
 * provider is wired with and the logout channels the ways of telling a client a session ended that are
 * wired, given by the discovery handler, never read from an enumeration, so that the document and the
 * endpoints cannot disagree; whether a request must be pushed is what every registered client requires
 * (RFC 9126 §5) and whether an unsigned request object is read what one of them registered (OIDC
 * Registration §2), read the same way; the rest is fixed by the module.
 */
final readonly class ProviderMetadata
{
    public const string CONTENT_TYPE = 'application/json';

    public const string OPENID_CONFIGURATION_PATH = '/.well-known/openid-configuration';

    public const string AUTHORIZATION_SERVER_METADATA_PATH = '/.well-known/oauth-authorization-server';

    public Scopes $scopesSupported;

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
     * @var list<KeyEncryptionAlgorithmInterface> no duplicate
     */
    public array $encryptionAlgorithmsSupported;

    /**
     * @var list<ContentEncryptionAlgorithmInterface> no duplicate
     */
    public array $encryptionMethodsSupported;

    /**
     * @var array<string, string>
     */
    public array $headers;

    /**
     * @param list<string> $claimsSupported "sub" added if missing
     * @param list<ResponseMode> $responseModesSupported the modes the authorization endpoint answers in, at least one
     * @param list<GrantType> $grantTypesSupported the grants the token endpoint serves, at least one
     * @param list<ClientAuthenticationMethodInterface> $clientAuthenticationMethodsSupported the methods the endpoints that authenticate a client take, at least one
     * @param list<string> $acrValuesSupported the classes of the policy of the tenant a login can prove, at least one
     * @param list<SignatureAlgorithmInterface> $signingAlgorithmsSupported the algorithms the provider signs its JWS with, at least one
     * @param list<LogoutChannel> $logoutChannelsSupported the ways of telling a client a session ended the integration serves, none of them if it serves none
     * @param list<KeyEncryptionAlgorithmInterface> $encryptionAlgorithmsSupported the "alg" the provider encrypts with and is encrypted to with, none of them where nothing is wired
     * @param list<ContentEncryptionAlgorithmInterface> $encryptionMethodsSupported the "enc" a payload is encrypted with, none of them where nothing is wired
     * @param ProviderEndpoints|null $mutualTlsEndpoints the same endpoints where a client presenting a certificate reaches them (RFC 8705 §5), null when no listener of the deployment asks for one
     * @param bool $requiresPushedAuthorizationRequests whether every client of the tenant only starts an authorization request by pushing it (RFC 9126 §5)
     * @param bool $acceptsUnsignedRequestObjects whether a client of the tenant registered "request_object_signing_alg": "none" (OIDC Registration §2), which is what announces "none" beside the algorithms
     * @param int $maxAge how long a client may cache the document, in seconds
     */
    public function __construct(
        public Issuer $issuer,
        public ProviderEndpoints $endpoints,
        public ?ProviderEndpoints $mutualTlsEndpoints,
        public bool $requiresPushedAuthorizationRequests,
        public bool $acceptsUnsignedRequestObjects,
        Scopes $scopesSupported,
        array $claimsSupported,
        array $responseModesSupported,
        array $grantTypesSupported,
        array $clientAuthenticationMethodsSupported,
        array $acrValuesSupported,
        array $signingAlgorithmsSupported,
        array $logoutChannelsSupported,
        array $encryptionAlgorithmsSupported,
        array $encryptionMethodsSupported,
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
        $scopes = new Scopes([Scope::openid(), ...$scopesSupported->all]);
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
        $this->encryptionAlgorithmsSupported = array_values(array_unique($encryptionAlgorithmsSupported, SORT_REGULAR));
        $this->encryptionMethodsSupported = array_values(array_unique($encryptionMethodsSupported, SORT_REGULAR));
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
        return $this->issuer->origin() . self::AUTHORIZATION_SERVER_METADATA_PATH . $this->issuer->path;
    }

    /**
     * In the order of OIDC Discovery §3, then RFC 8414 §2, RFC 9126 §5, RFC 9701 §6, RFC 9207 §3,
     * RP-Initiated Logout §2.1, RFC 8705 §3.3 and §5, RFC 9449 §5.1, JARM §3. The members that say what
     * is encrypted come in pairs, an "alg" and an "enc", and are named by the document they describe.
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
            'scopes_supported' => $this->scopesSupported->values(),
            'response_types_supported' => ['code'],
            'response_modes_supported' => self::values($this->announcedResponseModes()),
            'grant_types_supported' => self::values($this->grantTypesSupported),
            'acr_values_supported' => $this->acrValuesSupported,
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => $this->algorithmNames(),
            ...$this->encryptionOf('id_token_encryption'),
            // OIDC Discovery §3 and OIDC Core §5.3.2: a client may have the UserInfo answer as a JWT
            // signed by the tenant, encrypted, or both; one that registers none of these keeps the JSON
            'userinfo_signing_alg_values_supported' => $this->algorithmNames(),
            ...$this->encryptionOf('userinfo_encryption'),
            'token_endpoint_auth_methods_supported' => $this->methodNames($this->clientAuthenticationMethodsSupported),
            'token_endpoint_auth_signing_alg_values_supported' => $this->assertionSigningAlgorithms($this->clientAuthenticationMethodsSupported),
            'claims_supported' => $this->claimsSupported,
            'claims_parameter_supported' => true,
            // OIDC Discovery §3, RFC 9101 §10.5: both ways in are served, and a "request_uri" is read
            // back only from a URL its client registered, which decision 0006 makes a rule and not an
            // option. The algorithms are the ones the provider verifies signatures with; "none" is
            // beside them only when a client of the tenant registered it (issue #98).
            'request_parameter_supported' => true,
            'request_uri_parameter_supported' => true,
            'require_request_uri_registration' => true,
            'request_object_signing_alg_values_supported' => $this->requestObjectSigningAlgorithms(),
            ...$this->encryptionOf('request_object_encryption'),
            'code_challenge_methods_supported' => self::values(CodeChallengeMethod::cases()),
            'revocation_endpoint' => $this->endpoints->revocation,
            'revocation_endpoint_auth_methods_supported' => $this->methodNames($this->clientAuthenticationMethodsSupported),
            'revocation_endpoint_auth_signing_alg_values_supported' => $this->assertionSigningAlgorithms($this->clientAuthenticationMethodsSupported),
            // RFC 9126 §5: where a request is pushed, and whether pushing it is the only way in, which
            // is what every client registered here requires and not a switch of the deployment (§6)
            'pushed_authorization_request_endpoint' => $this->endpoints->pushedAuthorizationRequest,
            'require_pushed_authorization_requests' => $this->requiresPushedAuthorizationRequests,
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
            // RFC 8705 §3.3: whether the provider binds an access token to the certificate its client
            // presented, which is whether a method that proves one is wired and nothing else
            'tls_client_certificate_bound_access_tokens' => $this->bindsAccessTokensToCertificates(),
            // RFC 9449 §5.1: what a proof of possession may be signed with, which is what the provider
            // is wired with and verifies every other signature with; a client binding its tokens to a
            // key signs with one of these and with nothing else
            'dpop_signing_alg_values_supported' => $this->algorithmNames(),
            ...$this->authorizationResponseSigning(),
            ...$this->mutualTlsEndpointAliases(),
        ];
    }

    public function toJson(): string
    {
        return JwtPayload::encode($this->toArray());
    }

    /**
     * Multiple Response Type Encoding Practices §2.1 and JARM §2.1: the modes the integration wired,
     * plus "jwt" when one of them signs the answer. "jwt" delivers nothing of its own, it names the
     * signed mode the response type defaults to, so it is announced because a signed mode is wired and
     * never because it is listed somewhere (issue #98).
     *
     * @return non-empty-list<ResponseMode>
     */
    private function announcedResponseModes(): array
    {
        return $this->signsAnswers() ? [...$this->responseModesSupported, ResponseMode::Jwt] : $this->responseModesSupported;
    }

    /**
     * JARM §3: what a signed authorization response may be signed with, which is what the provider signs
     * every other JWS with, and what it may be encrypted to a key of the client with. A deployment that
     * wires no signed mode announces nothing at all here rather than empty lists: there is no answer to
     * sign, so there is none to encrypt either.
     *
     * @return array<string, mixed>
     */
    private function authorizationResponseSigning(): array
    {
        return (
            $this->signsAnswers()
                ? [
                    'authorization_signing_alg_values_supported' => $this->algorithmNames(),
                    ...$this->encryptionOf('authorization_encryption'),
                ] : []
        );
    }

    private function signsAnswers(): bool
    {
        return array_any($this->responseModesSupported, static fn (ResponseMode $mode): bool => $mode->signsTheAnswer());
    }

    /**
     * OIDC Discovery §3: what a request object of this provider may be signed with. The algorithms are
     * the ones the provider is wired with, and "none" is announced when a client of the tenant
     * registered it and never otherwise: a deployment whose clients all sign their objects does not
     * announce that it would read an unsigned one.
     *
     * @return non-empty-list<string>
     */
    private function requestObjectSigningAlgorithms(): array
    {
        $algorithms = $this->algorithmNames();

        return $this->acceptsUnsignedRequestObjects ? [...$algorithms, UnsignedRequestObjects::ALGORITHM] : $algorithms;
    }

    /**
     * OIDC Discovery §3: what is encrypted, and with what. The key management algorithms and the content
     * encryption ones the provider is wired with answer for every kind of document at once, because the
     * provider opens and mints them all with the same list: a request object a client encrypts to it, and
     * an ID token, a UserInfo answer and a signed authorization response it encrypts to a key of the
     * client. The two lists travel together, an "alg" encrypting nothing without an "enc" and the other
     * way round, so a deployment that wires neither announces none of these members rather than pairs of
     * empty lists a client would read as a promise.
     *
     * @param non-empty-string $member the kind of document, as the registry of OIDC Discovery §3 names it
     *
     * @return array<string, mixed>
     */
    private function encryptionOf(string $member): array
    {
        if ($this->encryptionAlgorithmsSupported === [] || $this->encryptionMethodsSupported === []) {
            return [];
        }

        return [
            $member . '_alg_values_supported' => array_map(
                static fn (KeyEncryptionAlgorithmInterface $algorithm): string => $algorithm->name(),
                $this->encryptionAlgorithmsSupported,
            ),
            $member . '_enc_values_supported' => array_map(
                static fn (ContentEncryptionAlgorithmInterface $algorithm): string => $algorithm->name(),
                $this->encryptionMethodsSupported,
            ),
        ];
    }

    /**
     * RFC 8705 §3.3, derived from the wired methods as every other list of this document is (issue #98):
     * a provider that authenticates no client by its certificate binds no token to one.
     */
    private function bindsAccessTokensToCertificates(): bool
    {
        return array_any(
            $this->clientAuthenticationMethodsSupported,
            static fn (ClientAuthenticationMethodInterface $method): bool => $method instanceof CertificateBindingMethodInterface,
        );
    }

    /**
     * RFC 8705 §5: where a client that presents a certificate reaches the endpoints that authenticate it
     * and the resources that honour a bound token. The aliases are the endpoints themselves, located a
     * second time by the integration on the host its listener asks for a certificate on, so that the two
     * cannot name different things; a deployment that has no such host announces no alias at all rather
     * than an object naming the ordinary endpoints.
     *
     * @return array<string, mixed>
     */
    private function mutualTlsEndpointAliases(): array
    {
        $endpoints = $this->mutualTlsEndpoints;
        if ($endpoints === null) {
            return [];
        }

        return [
            'mtls_endpoint_aliases' => [
                'token_endpoint' => $endpoints->token,
                'userinfo_endpoint' => $endpoints->userinfo,
                'introspection_endpoint' => $endpoints->introspection,
                'revocation_endpoint' => $endpoints->revocation,
                'pushed_authorization_request_endpoint' => $endpoints->pushedAuthorizationRequest,
            ],
        ];
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
        return array_values(array_filter(
            $this->clientAuthenticationMethodsSupported,
            static fn (ClientAuthenticationMethodInterface $method): bool => $method->authenticatesClient(),
        ));
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

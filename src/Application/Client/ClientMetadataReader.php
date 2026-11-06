<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use function array_any;
use function array_diff;
use function array_find;
use function array_keys;
use function array_map;
use function array_search;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Key\SignatureAlgorithmInterface;
use Beffroi\Core\Exception\InvalidArgumentException as CoreInvalidArgumentException;
use Beffroi\Core\Exception\UnsupportedAlgorithmException;
use Beffroi\Core\Port\ContentEncryptionAlgorithmsInterface;
use Beffroi\Core\Port\KeyEncryptionAlgorithmsInterface;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Oidc\Application\Ciba\DeliveryModeNames;
use Beffroi\Oidc\Application\Key\AlgorithmNames;
use Beffroi\Oidc\Application\Token\GrantNames;
use Beffroi\Oidc\Application\Token\ShapeNames;
use Beffroi\Oidc\Domain\Authorization\ResponseTypeNames;
use Beffroi\Oidc\Domain\Ciba\DeliveryModeInterface;
use Beffroi\Oidc\Domain\Client\AccessTokenShapeInterface;
use Beffroi\Oidc\Domain\Client\Certificate\CertificateIdentities;
use Beffroi\Oidc\Domain\Client\Certificate\CertificateIdentityInterface;
use Beffroi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientPresentation;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Client\InitiateLoginUri;
use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Beffroi\Oidc\Domain\Client\Metadata\GrantedMembers;
use Beffroi\Oidc\Domain\Client\Metadata\NestedMembers;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Client\RequestUri;
use Beffroi\Oidc\Domain\Client\RequestObject\AnyRegisteredAlgorithm;
use Beffroi\Oidc\Domain\Client\RequestObject\OneRegisteredAlgorithm;
use Beffroi\Oidc\Domain\Client\RequestObject\RequestObjectSigningInterface;
use Beffroi\Oidc\Domain\Client\RequestObject\UnsignedRequestObjects;
use Beffroi\Oidc\Domain\Client\ResponseEncryption;
use Beffroi\Oidc\Domain\Client\ResponseFormat;
use Beffroi\Oidc\Domain\Client\TokenExchange;
use Beffroi\Oidc\Domain\Exchange\MayAct;
use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\ClientSubject;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use Beffroi\Oidc\Exception\InvalidRedirectUriException;
use Beffroi\Oidc\Exception\UnreadableCertificateException;
use Beffroi\Oidc\Exception\UnreadableClientMetadataException;
use Beffroi\Oidc\Port\CertificateReaderInterface;
use Beffroi\Oidc\Port\ClientAuthenticationMethodsInterface;
use Beffroi\Oidc\Port\PresentedTokenTypesInterface;
use Beffroi\Oidc\Port\ServedAccessTokenShapesInterface;
use Beffroi\Oidc\Port\ServedAuthorizationDetailTypesInterface;
use Beffroi\Oidc\Port\ServedDeliveryModesInterface;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use Beffroi\Oidc\Port\AssignedSubjectTypesInterface;
use function implode;
use function in_array;
use function is_array;
use function is_bool;
use function is_string;
use function sprintf;

/**
 * RFC 7591 §2, OIDC Registration §2
 *
 * Strict on purpose: nothing is cast, and a member nobody reads is refused rather than ignored.
 */
final readonly class ClientMetadataReader
{
    private const array MEMBERS = [
        'client_name',
        'client_uri',
        'logo_uri',
        'policy_uri',
        'tos_uri',
        'contacts',
        'redirect_uris',
        'post_logout_redirect_uris',
        'grant_types',
        'response_types',
        'scope',
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
        'tls_client_certificate_bound_access_tokens',
        'dpop_bound_access_tokens',
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
        'authorization_details_types',
        'backchannel_token_delivery_mode',
        'backchannel_client_notification_endpoint',
        'token_exchange',
        'may_act',
        'subject_type',
        'sector_identifier_uri',
        'initiate_login_uri',
        'software_id',
        'software_version',
        // Never read as metadata: listed so that a tenant whose mode reads no statement ignores it.
        'software_statement',
        ...CertificateIdentities::NAMES,
    ];

    public function __construct(
        private SignatureAlgorithmsInterface $algorithms,
        private ClientAuthenticationMethodsInterface $methods,
        private ServedGrantsInterface $grants,
        private ServedAccessTokenShapesInterface $shapes,
        private CertificateReaderInterface $certificates,
        private KeyEncryptionAlgorithmsInterface $keyEncryption,
        private ContentEncryptionAlgorithmsInterface $contentEncryption,
        private ServedDeliveryModesInterface $deliveryModes,
        private PresentedTokenTypesInterface $tokenTypes,
        private ServedAuthorizationDetailTypesInterface $authorizationDetailTypes,
        private AssignedSubjectTypesInterface $subjects,
    ) {
    }

    /**
     * @throws UnreadableClientMetadataException
     */
    public function read(string $clientId, ClientMetadata $metadata, bool $secretIsHeld = false): ClientRegistration
    {
        $unknown = array_diff($metadata->members(), self::MEMBERS);
        if ($unknown !== []) {
            throw new InvalidClientMetadataException(
                null,
                null,
                sprintf('The client "%s" has unknown keys: %s.', $clientId, implode(', ', $unknown)),
            );
        }

        $method = $this->authenticationMethodOf($clientId, $metadata);
        $redirectUris = $this->redirectUris($clientId, 'redirect_uris', $metadata);
        $grantTypes = $this->grantTypes($clientId, $metadata);
        $tokenExchange = $this->tokenExchange($clientId, $metadata);
        $this->assertGrantsHoldWithTheRest(
            $clientId,
            $grantTypes,
            $redirectUris,
            $method,
            $tokenExchange,
            $this->responseTypes($clientId, $metadata),
        );

        $idToken = ResponseFormat::signed(
            $this->algorithm($clientId, 'id_token_signed_response_alg', $metadata),
            $this->encryption($clientId, 'id_token', $metadata),
        );
        $authorizationResponse = ResponseFormat::signed(
            $this->algorithm($clientId, 'authorization_signed_response_alg', $metadata),
            $this->encryption($clientId, 'authorization', $metadata),
        );
        $userInfoEncryption = $this->encryption($clientId, 'userinfo', $metadata);
        $userInfo = $metadata->has('userinfo_signed_response_alg')
            ? ResponseFormat::signed($this->algorithm($clientId, 'userinfo_signed_response_alg', $metadata), $userInfoEncryption)
            : ResponseFormat::unsigned($userInfoEncryption);

        $jwks = $this->jwks($clientId, $metadata);

        try {
            $registration = new ClientRegistration(
                $clientId,
                $this->presentation($clientId, $metadata),
                $method,
                $secretIsHeld,
                $redirectUris,
                $this->accessTokenShape($clientId, $metadata),
                $this->redirectUris($clientId, 'post_logout_redirect_uris', $metadata),
                $grantTypes,
                $this->scopes($clientId, $metadata),
                $this->flag($clientId, 'requires_consent', $metadata, true),
                $idToken,
                $this->flag($clientId, 'requires_pkce', $metadata, true),
                $this->clientUri($clientId, 'backchannel_logout_uri', $metadata),
                $this->flag($clientId, 'backchannel_logout_session_required', $metadata),
                $this->clientUri($clientId, 'frontchannel_logout_uri', $metadata),
                $this->flag($clientId, 'frontchannel_logout_session_required', $metadata),
                $jwks,
                $this->clientUri($clientId, 'jwks_uri', $metadata),
                $this->certificateIdentity($clientId, $metadata),
                $this->flag($clientId, 'require_pushed_authorization_requests', $metadata),
                $this->requestObjectSigning($clientId, $metadata),
                $this->requestUris($clientId, $metadata),
                $authorizationResponse,
                $userInfo,
                $this->flag($clientId, 'require_sender_constrained_tokens', $metadata),
                $this->flag($clientId, 'require_signed_request_object', $metadata),
                $this->resources($clientId, $metadata),
                $this->deliveryMode($clientId, $metadata),
                $this->clientUri($clientId, 'backchannel_client_notification_endpoint', $metadata),
                $tokenExchange,
                $this->mayAct($clientId, $metadata),
                $this->authorizationDetailsTypes($clientId, $metadata),
                $this->flag($clientId, 'tls_client_certificate_bound_access_tokens', $metadata),
                $this->subjectType($clientId, $metadata),
                $this->clientUri($clientId, 'sector_identifier_uri', $metadata),
                $this->initiateLoginUri($clientId, $metadata),
                $this->text($clientId, 'software_id', $metadata),
                $this->text($clientId, 'software_version', $metadata),
                $this->flag($clientId, 'dpop_bound_access_tokens', $metadata),
            );
        } catch (InvalidArgumentException $exception) {
            throw $exception instanceof UnreadableClientMetadataException
                ? $exception
                : self::keeping($exception);
        }

        foreach ([$idToken, $userInfo, $authorizationResponse] as $format) {
            self::assertAddressable($clientId, $format, $jwks);
        }
        $this->subjects->assertAssignable($registration);

        return $registration;
    }

    private function presentation(string $clientId, ClientMetadata $metadata): ClientPresentation
    {
        return new ClientPresentation(
            $this->text($clientId, 'client_name', $metadata) ?? $clientId,
            $this->clientUri($clientId, 'client_uri', $metadata),
            $this->clientUri($clientId, 'logo_uri', $metadata),
            $this->clientUri($clientId, 'policy_uri', $metadata),
            $this->clientUri($clientId, 'tos_uri', $metadata),
            $this->stringList($clientId, 'contacts', $metadata),
        );
    }

    private function scopes(string $clientId, ClientMetadata $metadata): Scopes
    {
        $scope = $this->text($clientId, 'scope', $metadata);
        if ($scope === null) {
            return new Scopes([Scope::openid()]);
        }

        try {
            return new Scopes(Scope::parseList($scope));
        } catch (InvalidArgumentException $exception) {
            throw self::keeping($exception, 'scope', $metadata->sourceOf('scope'));
        }
    }

    /**
     * @return list<string>
     */
    private function responseTypes(string $clientId, ClientMetadata $metadata): array
    {
        $registered = $this->stringList($clientId, 'response_types', $metadata);
        foreach ($registered as $name) {
            if ($name !== ResponseTypeNames::CODE) {
                throw $this->oneOf($clientId, 'response_types', $metadata, [ResponseTypeNames::CODE]);
            }
        }

        return $registered;
    }

    /**
     * @return non-empty-string|null
     */
    private function subjectType(string $clientId, ClientMetadata $metadata): ?string
    {
        $name = $this->text($clientId, 'subject_type', $metadata);
        if ($name === null) {
            return null;
        }
        $assigned = $this->subjects->assignedSubjectTypes();
        if (! in_array($name, $assigned, true)) {
            throw $this->oneOf($clientId, 'subject_type', $metadata, $assigned);
        }

        return $name;
    }

    private function algorithm(string $clientId, string $option, ClientMetadata $metadata): SignatureAlgorithmInterface
    {
        $name = $this->text($clientId, $option, $metadata);
        if ($name === null) {
            return $this->algorithms->defaultAlgorithm();
        }
        try {
            return $this->algorithms->named($name);
        } catch (UnsupportedAlgorithmException $exception) {
            throw $this->oneOf($clientId, $option, $metadata, AlgorithmNames::of($this->algorithms->all()), $exception);
        }
    }

    /**
     * OIDC Registration §2, JARM §3
     *
     * Both or neither: §2 defaults "enc" to A128CBC-HS256, which is not wired and would fail the first document.
     */
    private function encryption(string $clientId, string $prefix, ClientMetadata $metadata): ?ResponseEncryption
    {
        $algorithmOption = $prefix . '_encrypted_response_alg';
        $methodOption = $prefix . '_encrypted_response_enc';
        $carriesAlgorithm = $metadata->has($algorithmOption);
        $carriesMethod = $metadata->has($methodOption);
        if (! $carriesAlgorithm && ! $carriesMethod) {
            return null;
        }
        if (! $carriesAlgorithm || ! $carriesMethod) {
            throw new InvalidClientMetadataException(
                $carriesAlgorithm ? $methodOption : $algorithmOption,
                $metadata->sourceOf($carriesAlgorithm ? $algorithmOption : $methodOption),
                sprintf(
                    'The client "%s" registers %s without %s; a document is encrypted to a key under an "alg" and its payload under an "enc", and this provider takes no default for either.',
                    $clientId,
                    $carriesAlgorithm ? $algorithmOption : $methodOption,
                    $carriesAlgorithm ? $methodOption : $algorithmOption,
                ),
            );
        }
        $algorithmName = $metadata->value($algorithmOption);
        $methodName = $metadata->value($methodOption);
        if (! is_string($algorithmName) || ! is_string($methodName)) {
            throw new InvalidClientMetadataException(
                is_string($algorithmName) ? $methodOption : $algorithmOption,
                $metadata->sourceOf(is_string($algorithmName) ? $methodOption : $algorithmOption),
                sprintf('The %s and %s options of the client "%s" must be strings.', $algorithmOption, $methodOption, $clientId),
            );
        }

        try {
            $algorithm = $this->keyEncryption->named($algorithmName);
        } catch (UnsupportedAlgorithmException $exception) {
            throw $this->oneOf($clientId, $algorithmOption, $metadata, AlgorithmNames::of($this->keyEncryption->all()), $exception);
        }

        try {
            $method = $this->contentEncryption->named($methodName);
        } catch (UnsupportedAlgorithmException $exception) {
            throw $this->oneOf($clientId, $methodOption, $metadata, AlgorithmNames::of($this->contentEncryption->all()), $exception);
        }

        return new ResponseEncryption($algorithm, $method);
    }

    /**
     * A set behind a "jwks_uri" is read only when a document is minted, so only an inline set is checked here.
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

        throw new InvalidClientMetadataException(
            'jwks',
            null,
            sprintf(
                'The client "%s" registers a response encrypted under "%s" but publishes no key it can be addressed to: its "jwks" holds no %s key that is not reserved for signing.',
                $clientId,
                $encryption->algorithm->name(),
                $encryption->algorithm->keyType(),
            ),
        );
    }

    /**
     * What an initial access token gives, read as the registration of each client it registers reads it, so that a token
     * that gives what this provider cannot serve is never issued.
     *
     * @throws UnreadableClientMetadataException
     */
    public function assertGivable(string $tokenName, GrantedMembers $granted): void
    {
        $metadata = new ClientMetadata([$granted]);
        $this->resources($tokenName, $metadata);
        $this->accessTokenShape($tokenName, $metadata);
        $this->flag($tokenName, 'require_sender_constrained_tokens', $metadata);
        $this->tokenExchange($tokenName, $metadata);
        $this->mayAct($tokenName, $metadata);
    }

    /**
     * @throws UnreadableClientMetadataException
     */
    public function authenticationMethodOf(string $clientId, ClientMetadata $metadata): ClientAuthenticationMethodInterface
    {
        $wired = $this->methods->clientAuthenticationMethods();

        return $this->named($clientId, 'token_endpoint_auth_method', $metadata, $wired, MethodNames::of($wired));
    }

    private function accessTokenShape(string $clientId, ClientMetadata $metadata): AccessTokenShapeInterface
    {
        $wired = $this->shapes->servedAccessTokenShapes();

        return $this->named($clientId, 'access_token_format', $metadata, $wired, ShapeNames::of($wired));
    }

    /**
     * The wired one the client registered by name, or the first when it registered none.
     *
     * @template T of object
     *
     * @param non-empty-list<T> $wired
     * @param non-empty-list<string> $names in the order of $wired
     *
     * @throws UnreadableClientMetadataException
     *
     * @return T
     */
    private function named(string $clientId, string $option, ClientMetadata $metadata, array $wired, array $names): object
    {
        $name = $this->text($clientId, $option, $metadata);
        if ($name === null) {
            return $wired[0];
        }
        $at = array_search($name, $names, true);

        return $at === false ? throw $this->oneOf($clientId, $option, $metadata, $names) : $wired[$at];
    }

    /**
     * @throws UnreadableClientMetadataException
     *
     * @return list<GrantTypeName>
     */
    private function grantTypes(string $clientId, ClientMetadata $metadata): array
    {
        $served = $this->grants->servedGrantTypes();
        $registered = [];
        foreach ($this->stringList($clientId, 'grant_types', $metadata) as $name) {
            $grantType = array_find($served, static fn (GrantTypeName $wired): bool => $wired->value === $name);
            if ($grantType === null) {
                throw $this->oneOf($clientId, 'grant_types', $metadata, GrantNames::of($served));
            }
            $registered[] = $grantType;
        }

        $isRegistered = static fn (GrantTypeName $grantType): bool => array_any(
            $registered,
            static fn (GrantTypeName $one): bool => $one->equals($grantType),
        );
        $spends = array_find($this->grants->spendingRefreshTokens(), $isRegistered);
        if ($spends !== null && ! array_any($this->grants->issuingRefreshTokens(), $isRegistered)) {
            throw new InvalidClientMetadataException(
                'grant_types',
                $metadata->sourceOf('grant_types'),
                sprintf(
                    'The client "%s" cannot spend with "%s" a refresh token it has no way to obtain: register it for one of: %s.',
                    $clientId,
                    $spends->value,
                    implode(', ', GrantNames::of($this->grants->issuingRefreshTokens())),
                ),
            );
        }

        return $registered;
    }

    /**
     * RFC 6749 §2.1, §3.1.2.2, OIDC Registration §2
     *
     * @param list<GrantTypeName> $registered
     * @param list<RedirectUri> $redirectUris
     * @param list<string> $responseTypes
     *
     * @throws UnreadableClientMetadataException
     */
    private function assertGrantsHoldWithTheRest(
        string $clientId,
        array $registered,
        array $redirectUris,
        ClientAuthenticationMethodInterface $method,
        ?TokenExchange $tokenExchange,
        array $responseTypes,
    ): void {
        if ($registered === []) {
            // A client that registers no grant is refused by the registration itself.
            return;
        }
        $isRegistered = static fn (GrantTypeName $grantType): bool => array_any(
            $registered,
            static fn (GrantTypeName $one): bool => $one->equals($grantType),
        );
        $sendsTheUser = array_find($this->grants->sendingTheUserToTheClient(), $isRegistered);
        if ($sendsTheUser !== null && $redirectUris === []) {
            throw new InvalidRedirectUriException(
                'redirect_uris',
                null,
                sprintf(
                    'The client "%s" is registered for "%s", whose flow sends the user back to it, and therefore registers at least one redirect URI (RFC 6749 section 3.1.2.2).',
                    $clientId,
                    $sendsTheUser->value,
                ),
            );
        }
        if ($sendsTheUser === null && $redirectUris !== []) {
            throw new InvalidRedirectUriException(
                'redirect_uris',
                null,
                sprintf(
                    'The client "%s" registers redirect URIs and no grant that would send the user to one: register one of: %s.',
                    $clientId,
                    implode(', ', GrantNames::of($this->grants->sendingTheUserToTheClient())),
                ),
            );
        }
        if ($sendsTheUser === null && $responseTypes !== []) {
            throw new InvalidClientMetadataException(
                'response_types',
                null,
                sprintf(
                    'The client "%s" registers the response type "%s" and no grant that would answer with one: register one of: %s (OIDC Registration section 2).',
                    $clientId,
                    $responseTypes[0],
                    implode(', ', GrantNames::of($this->grants->sendingTheUserToTheClient())),
                ),
            );
        }
        $exchanges = array_find($this->grants->exchangingTokens(), $isRegistered);
        if ($exchanges !== null && $tokenExchange === null) {
            throw new InvalidClientMetadataException(
                'token_exchange',
                null,
                sprintf(
                    'The client "%s" is registered for "%s", which turns a token into another token, and therefore declares under "token_exchange" what it may present and what it may ask for (RFC 8693 section 2.1).',
                    $clientId,
                    $exchanges->value,
                ),
            );
        }
        if ($exchanges === null && $tokenExchange !== null) {
            throw new InvalidClientMetadataException(
                'token_exchange',
                null,
                sprintf(
                    'The client "%s" declares a token_exchange and no grant that would exchange anything: register one of: %s.',
                    $clientId,
                    implode(', ', GrantNames::of($this->grants->exchangingTokens())),
                ),
            );
        }
        if ($exchanges !== null) {
            self::asASubject($clientId);
        }
        $authenticated = array_find($this->grants->requiringClientAuthentication(), $isRegistered);
        if ($authenticated !== null && ! $method->authenticatesClient()) {
            throw new InvalidClientMetadataException(
                'token_endpoint_auth_method',
                null,
                sprintf(
                    'The client "%s" is registered for "%s", which requires client authentication, and authenticates with %s, which proves nothing (RFC 6749 section 2.1).',
                    $clientId,
                    $authenticated->value,
                    $method->name(),
                ),
            );
        }
        if (array_find($this->grants->actingForTheClientItself(), $isRegistered) !== null) {
            self::asASubject($clientId);
        }
    }

    /**
     * RFC 8693 §4.1, §4.4
     *
     * @throws UnreadableClientMetadataException
     */
    private static function asASubject(string $clientId): void
    {
        try {
            ClientSubject::ofIdentifier($clientId);
        } catch (InvalidArgumentException $exception) {
            throw self::keeping($exception);
        }
    }

    /**
     * RFC 8693 §2.1
     *
     * @throws UnreadableClientMetadataException
     */
    private function tokenExchange(string $clientId, ClientMetadata $metadata): ?TokenExchange
    {
        if (! $metadata->has('token_exchange')) {
            return null;
        }
        $declared = $metadata->value('token_exchange');
        $source = $metadata->sourceOf('token_exchange');
        if (! is_array($declared)) {
            throw new InvalidClientMetadataException(
                'token_exchange',
                $source,
                sprintf('The token_exchange option of the client "%s" must be a map (RFC 8693 section 2.1).', $clientId),
            );
        }
        /** @var array<string, mixed> $declared */
        $unknown = array_diff(array_keys($declared), ['subject_token_types', 'may_act_for_a_user']);
        if ($unknown !== []) {
            throw new InvalidClientMetadataException(
                'token_exchange',
                $source,
                sprintf('The token_exchange option of the client "%s" has unknown keys: %s.', $clientId, implode(', ', $unknown)),
            );
        }
        $inside = new ClientMetadata([new NestedMembers($source, $declared)]);
        $wired = array_map(static fn (TokenTypeIdentifier $type): string => $type->value, $this->tokenTypes->presentedTokenTypes());
        $types = [];
        foreach ($this->stringList($clientId, 'subject_token_types', $inside) as $name) {
            if (! in_array($name, $wired, true)) {
                throw new InvalidClientMetadataException(
                    'token_exchange',
                    $source,
                    sprintf(
                        'The client "%s" may present a "%s", which this provider does not read; the wired token types are %s (RFC 8693 section 3).',
                        $clientId,
                        $name,
                        implode(', ', $wired),
                    ),
                );
            }
            $types[] = new TokenTypeIdentifier($name);
        }
        if ($types === []) {
            throw new InvalidClientMetadataException(
                'token_exchange',
                $source,
                sprintf(
                    'The client "%s" registers at least one subject_token_types, among %s (RFC 8693 section 2.1).',
                    $clientId,
                    implode(', ', $wired),
                ),
            );
        }

        return new TokenExchange($types, $this->flag($clientId, 'may_act_for_a_user', $inside));
    }

    /**
     * RFC 8693 §4.4
     *
     * @throws UnreadableClientMetadataException
     */
    private function mayAct(string $clientId, ClientMetadata $metadata): ?MayAct
    {
        $subject = $this->text($clientId, 'may_act', $metadata);
        if ($subject === null) {
            return null;
        }
        try {
            return new MayAct(new Subject($subject));
        } catch (CoreInvalidArgumentException $exception) {
            throw new InvalidClientMetadataException(
                'may_act',
                $metadata->sourceOf('may_act'),
                sprintf('The may_act option of the client "%s" names a subject (OIDC Core section 2).', $clientId),
                $exception,
            );
        }
    }

    /**
     * RFC 8705 §2.1.2
     *
     * @throws UnreadableClientMetadataException
     */
    private function certificateIdentity(string $clientId, ClientMetadata $metadata): ?CertificateIdentityInterface
    {
        $registration = [];
        foreach (CertificateIdentities::NAMES as $key) {
            $registration[$key] = $this->text($clientId, $key, $metadata);
        }
        $subjectDn = $registration[CertificateIdentities::SUBJECT_DN];
        if ($subjectDn !== null) {
            try {
                $registration[CertificateIdentities::SUBJECT_DN] = $this->certificates->distinguishedName($subjectDn);
            } catch (UnreadableCertificateException $exception) {
                throw new InvalidClientMetadataException(
                    CertificateIdentities::SUBJECT_DN,
                    $metadata->sourceOf(CertificateIdentities::SUBJECT_DN),
                    sprintf('The %s option of the client "%s" must be a distinguished name of RFC 4514.', CertificateIdentities::SUBJECT_DN, $clientId),
                    $exception,
                );
            }
        }

        try {
            return CertificateIdentities::fromRegistration($registration);
        } catch (InvalidArgumentException $exception) {
            throw self::keeping($exception);
        }
    }

    /**
     * A request object is read unsigned only when the client registered "none", never by default.
     *
     * @throws UnreadableClientMetadataException
     */
    private function requestObjectSigning(string $clientId, ClientMetadata $metadata): RequestObjectSigningInterface
    {
        $name = $this->text($clientId, 'request_object_signing_alg', $metadata);
        if ($name === null) {
            return new AnyRegisteredAlgorithm();
        }
        if ($name === UnsignedRequestObjects::ALGORITHM) {
            return new UnsignedRequestObjects();
        }
        try {
            return new OneRegisteredAlgorithm($this->algorithms->named($name));
        } catch (UnsupportedAlgorithmException $exception) {
            throw new InvalidClientMetadataException(
                'request_object_signing_alg',
                $metadata->sourceOf('request_object_signing_alg'),
                sprintf(
                    'The request_object_signing_alg option of the client "%s" must be "%s" or one of: %s.',
                    $clientId,
                    UnsignedRequestObjects::ALGORITHM,
                    implode(', ', AlgorithmNames::of($this->algorithms->all())),
                ),
                $exception,
            );
        }
    }

    /**
     * @throws UnreadableClientMetadataException
     */
    private function jwks(string $clientId, ClientMetadata $metadata): ?ClientJwks
    {
        if (! $metadata->has('jwks')) {
            return null;
        }
        $jwks = $metadata->value('jwks');
        $source = $metadata->sourceOf('jwks');
        if (! is_array($jwks)) {
            throw new InvalidClientMetadataException(
                'jwks',
                $source,
                sprintf('The jwks option of the client "%s" must be a JWK Set (RFC 7517 section 5).', $clientId),
            );
        }

        try {
            return ClientJwks::fromDocument($jwks);
        } catch (InvalidArgumentException $exception) {
            throw self::keeping($exception, 'jwks', $source);
        }
    }

    /**
     * CIBA Core §4, §7.1
     *
     * No default: a client that registers no mode is a client of another flow.
     *
     * @throws UnreadableClientMetadataException
     */
    private function deliveryMode(string $clientId, ClientMetadata $metadata): ?DeliveryModeInterface
    {
        $name = $this->text($clientId, 'backchannel_token_delivery_mode', $metadata);
        if ($name === null) {
            return null;
        }
        $wired = DeliveryModeNames::of($this->deliveryModes->servedDeliveryModes());
        if (! in_array($name, $wired, true)) {
            throw new InvalidClientMetadataException(
                'backchannel_token_delivery_mode',
                $metadata->sourceOf('backchannel_token_delivery_mode'),
                sprintf(
                    'The client "%s" registers the backchannel token delivery mode "%s", which this provider is not wired with; it serves %s.',
                    $clientId,
                    $name,
                    $wired === [] ? 'none' : implode(', ', $wired),
                ),
            );
        }

        return $this->deliveryModes->named($name);
    }

    /**
     * RFC 8707 §2
     *
     * @throws UnreadableClientMetadataException
     *
     * @return list<ResourceIndicator>
     */
    private function resources(string $clientId, ClientMetadata $metadata): array
    {
        $resources = [];
        foreach ($this->stringList($clientId, 'resources', $metadata) as $value) {
            try {
                $resources[] = new ResourceIndicator($value);
            } catch (InvalidArgumentException $exception) {
                throw self::keeping($exception, 'resources', $metadata->sourceOf('resources'));
            }
        }

        return $resources;
    }

    /**
     * RFC 6749 §3.1.2, RP-Initiated Logout §2, RFC 7591 §3.2.2
     *
     * @throws UnreadableClientMetadataException
     *
     * @return list<RedirectUri>
     */
    private function redirectUris(string $clientId, string $option, ClientMetadata $metadata): array
    {
        $uris = [];
        foreach ($this->stringList($clientId, $option, $metadata) as $value) {
            try {
                $uris[] = new RedirectUri($value);
            } catch (InvalidArgumentException $exception) {
                throw new InvalidRedirectUriException($option, $metadata->sourceOf($option), $exception->getMessage(), $exception);
            }
        }

        return $uris;
    }

    /**
     * @throws UnreadableClientMetadataException
     *
     * @return list<RequestUri>
     */
    private function requestUris(string $clientId, ClientMetadata $metadata): array
    {
        $uris = [];
        foreach ($this->stringList($clientId, 'request_uris', $metadata) as $value) {
            try {
                $uris[] = new RequestUri($value);
            } catch (InvalidArgumentException $exception) {
                throw self::keeping($exception, 'request_uris', $metadata->sourceOf('request_uris'));
            }
        }

        return $uris;
    }

    /**
     * @throws UnreadableClientMetadataException
     */
    private function clientUri(string $clientId, string $option, ClientMetadata $metadata): ?ClientUri
    {
        $uri = $this->text($clientId, $option, $metadata);

        return $uri === null ? null : self::uri($uri, $option, $metadata->sourceOf($option));
    }

    /**
     * @throws UnreadableClientMetadataException
     */
    private function initiateLoginUri(string $clientId, ClientMetadata $metadata): ?InitiateLoginUri
    {
        $value = $this->text($clientId, 'initiate_login_uri', $metadata);
        if ($value === null) {
            return null;
        }
        try {
            return new InitiateLoginUri($value);
        } catch (InvalidArgumentException $exception) {
            throw self::keeping($exception, 'initiate_login_uri', $metadata->sourceOf('initiate_login_uri'));
        }
    }

    /**
     * @throws UnreadableClientMetadataException
     */
    private static function uri(string $value, string $option, string $source): ClientUri
    {
        try {
            return new ClientUri($value);
        } catch (InvalidArgumentException $exception) {
            throw self::keeping($exception, $option, $source);
        }
    }

    /**
     * @throws UnreadableClientMetadataException
     */
    private function text(string $clientId, string $option, ClientMetadata $metadata): ?string
    {
        if (! $metadata->has($option)) {
            return null;
        }
        $value = $metadata->value($option);
        if (! is_string($value)) {
            throw new InvalidClientMetadataException(
                $option,
                $metadata->sourceOf($option),
                sprintf('The %s option of the client "%s" must be a string.', $option, $clientId),
            );
        }

        return $value;
    }

    /**
     * RFC 9396 §11
     *
     * @throws UnreadableClientMetadataException
     *
     * @return list<string>
     */
    private function authorizationDetailsTypes(string $clientId, ClientMetadata $metadata): array
    {
        $served = $this->authorizationDetailTypes->servedAuthorizationDetailTypes();
        $registered = $this->stringList($clientId, 'authorization_details_types', $metadata);
        foreach ($registered as $name) {
            if (! in_array($name, $served, true)) {
                throw $this->oneOf(
                    $clientId,
                    'authorization_details_types',
                    $metadata,
                    $served === [] ? ['none: this provider is wired with no authorization detail type'] : $served,
                );
            }
        }

        return $registered;
    }

    /**
     * @param list<string> $wired
     */
    private function oneOf(
        string $clientId,
        string $option,
        ClientMetadata $metadata,
        array $wired,
        ?UnsupportedAlgorithmException $previous = null,
    ): InvalidClientMetadataException {
        return new InvalidClientMetadataException(
            $option,
            $metadata->sourceOf($option),
            sprintf('The %s option of the client "%s" must be one of: %s.', $option, $clientId, implode(', ', $wired)),
            $previous,
        );
    }

    /**
     * @throws UnreadableClientMetadataException
     */
    private function flag(string $clientId, string $key, ClientMetadata $metadata, bool $default = false): bool
    {
        if (! $metadata->has($key)) {
            return $default;
        }
        $value = $metadata->value($key);
        if (! is_bool($value)) {
            throw new InvalidClientMetadataException(
                $key,
                $metadata->sourceOf($key),
                sprintf('The %s option of the client "%s" must be a boolean.', $key, $clientId),
            );
        }

        return $value;
    }

    /**
     * @throws UnreadableClientMetadataException
     *
     * @return list<string>
     */
    private function stringList(string $clientId, string $key, ClientMetadata $metadata): array
    {
        if (! $metadata->has($key)) {
            return [];
        }
        $value = $metadata->value($key);
        $refusal = new InvalidClientMetadataException(
            $key,
            $metadata->sourceOf($key),
            sprintf('The %s option of the client "%s" must be a list of strings.', $key, $clientId),
        );
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

    private static function keeping(
        InvalidArgumentException $previous,
        ?string $member = null,
        ?string $source = null,
    ): InvalidClientMetadataException {
        return new InvalidClientMetadataException($member, $source, $previous->getMessage(), $previous);
    }
}

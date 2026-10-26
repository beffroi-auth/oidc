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
 * The one reader of the metadata a client is registered with (RFC 7591 §2, OIDC Registration §2). A member
 * is spelled here and nowhere else, whether a deployment declared it in its configuration, a client sent it
 * to the registration endpoint or a row kept what a client sent: it is the same registration wherever it
 * comes from, because there is one thing that reads it.
 *
 * It is strict. Nothing is cast, a value of another kind is refused rather than coerced, a member nobody
 * reads is refused rather than ignored, and every name a client registers is checked against what the
 * provider is wired with, where the registration and the wiring meet. A registration this reader does not
 * understand does not exist.
 *
 * It raises one kind of thing, `UnreadableClientMetadataException`, of which there is one subclass per error
 * code of RFC 7591 §3.2.2, each naming its own; it carries the member that does not hold and the source the
 * value came from. What that becomes is the caller's: a boot that stops for a declaration, a 400 for a client
 * that registered itself. The reader knows neither, and there is no branch in it for either.
 *
 * What differs between callers beyond that is what each passes in. The defaults of a deployment and those of
 * RFC 7591 §2 are sources read behind the members themselves (`DeploymentDefaults`, `SpecifiedDefaults`), so
 * a client that registers itself takes "authorization_code" and "client_secret_basic" where a declaration
 * takes the browser flow and its renewal, and neither is a case in here.
 */
final readonly class ClientMetadataReader
{
    /**
     * Every member this reader understands. A member outside this list is refused wherever it was written,
     * and a member this provider learns to read is added here and read below: one place, once.
     */
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
        // RFC 7591 §2.3: what a statement authorises with, read by the mode that is that authorisation
        // (SoftwareStatementAuthorization) and never as metadata. It is named here so that a client that
        // sends one to a tenant whose mode reads none is registered as if the member were absent, rather
        // than refused for a key nobody reads.
        'software_statement',
        ...CertificateIdentities::NAMES,
    ];

    /**
     * @param SignatureAlgorithmsInterface $algorithms what the provider signs with: a client registers one of those names, or none and takes the default
     * @param ClientAuthenticationMethodsInterface $methods what the provider authenticates clients with: a client registers one of those names
     * @param ServedGrantsInterface $grants what the provider serves at its token endpoint: a client registers those names and no other
     * @param ServedAccessTokenShapesInterface $shapes what the provider writes its access tokens in: a client registers one of those names, or none and takes the first
     * @param CertificateReaderInterface $certificates what writes a registered distinguished name the way it will be read out of a certificate (RFC 8705 §2.1.2)
     * @param KeyEncryptionAlgorithmsInterface $keyEncryption what the provider encrypts a document to a client with: a client registers one of those names, or none and receives nothing encrypted
     * @param ContentEncryptionAlgorithmsInterface $contentEncryption what the payload of such a document is encrypted with
     * @param ServedDeliveryModesInterface $deliveryModes how the provider is wired to tell a client that a backchannel request has been answered: a client of that flow registers one of those names, and every other client registers none
     * @param PresentedTokenTypesInterface $tokenTypes what the exchange is wired to read: a client of that grant registers those names and no other (RFC 8693 §3)
     * @param ServedAuthorizationDetailTypesInterface $authorizationDetailTypes what the provider is wired to read an "authorization_details" with: a client registers those names and no other (RFC 9396 §2, §11)
     * @param AssignedSubjectTypesInterface $subjects the kinds of "sub" the provider assigns one of (OIDC Core §8): a client registers one of those names, or none and takes the first, and what that kind needs of a registration is read here too
     */
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
     * @param string $clientId the identifier the registration is read under, drawn by the provider for a client that registered itself (RFC 7591 §3.2.1) and written by the deployment for a declared one
     * @param bool $secretIsHeld whether this provider holds a secret for that client although the metadata carries none: what a store knows from the column it keeps it in, RFC 7591 §2 having no member for a secret the provider assigned (§3.2.1)
     *
     * @throws UnreadableClientMetadataException when the registration does not hold together
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
            );
        } catch (InvalidArgumentException $exception) {
            // What the registration refuses is a rule between several members, which its message names: it
            // answers for itself and knows nothing of where its values came from. What a member refuses on
            // its own already says which one it was
            throw $exception instanceof UnreadableClientMetadataException
                ? $exception
                : self::keeping($exception);
        }

        foreach ([$idToken, $userInfo, $authorizationResponse] as $format) {
            self::assertAddressable($clientId, $format, $jwks);
        }
        // OIDC Core §8: what the kind of "sub" this client takes needs of a registration, asked of the kind
        // itself and read wherever the registration came from. What it demands of a client that registers
        // itself, and that a declaration of a deployment owes nobody, is read where a registration is
        // written (RegistrationHeldToItsSector).
        $this->subjects->assertAssignable($registration);

        return $registration;
    }

    /**
     * OIDC Registration §2: what a user is shown of the client that is asking, and how to reach whoever
     * answers for it. A client that registers no name is shown under its identifier, which is the only thing
     * this provider is sure of about it.
     */
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

    /**
     * RFC 7591 §2 "scope": the closed list of scopes this client may ask for, space-delimited as the
     * specification writes it and as a request writes it (RFC 6749 §3.3).
     */
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
     * OIDC Registration §2 "response_types": what this client asks the authorization endpoint to answer
     * with, among the ones this provider answers at all, which decision 0006 closes to a code
     * (ResponseTypeNames).
     * It is not kept: a response type a client may ask for is the grant it registered, and holding both
     * would be two places that must agree. What is checked is that they do.
     *
     * @return list<string> empty for a client that registered none, which RFC 7591 §2 reads as the one a flow
     *                      that sends the user back answers with
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
     * OIDC Core §8, OIDC Registration §2 "subject_type": the kind of "sub" this client registered, among the
     * kinds this provider resolves one for, which the resolvers name themselves. A kind nothing resolves is
     * refused here rather than answered with an identifier of another kind, as a grant nothing serves is.
     *
     * @return non-empty-string|null null for a client that registered none
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

    /**
     * A JWS algorithm a client registers for a kind of thing the provider signs for it (OIDC Registration
     * §2, JARM §3): one of the names the provider is wired with, or none and the default it signs with.
     * Written once for the options that carry one, so that they cannot read their names differently.
     */
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
     * The pair a client registers to have one kind of document encrypted for it (OIDC Registration §2,
     * JARM §3): the "alg" the content encryption key is wrapped under, and the "enc" the payload is
     * encrypted with. Both or neither, and never one alone: §2 lets an "enc" be left out and defaults it
     * to "A128CBC-HS256", which this provider is not wired with, so taking that default would accept at
     * boot a registration that fails on the first document. Written once for the three kinds, so that
     * they cannot read their names differently.
     *
     * @param string $prefix the kind of document, as the registration names it
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
     * The method the client registers, among those the provider is wired with (issue #98): a name
     * nothing authenticates with is refused with the list of the wired ones, because nothing upstream can
     * know that list.
     *
     * Read on its own by the registration endpoint, which owes two answers before the registration
     * exists: whether to draw a secret, since the provider assigns one exactly when the registered
     * method proves one (RFC 7591 §3.2.1), and whether the policy of the tenant writes anything on this
     * registration, since it exempts a confidential client from PKCE and never a public one (decision
     * 0017). Both are the same question about the same member, so it is read here and not a second time.
     *
     * @throws UnreadableClientMetadataException when the client registered a name nothing is wired with
     */
    public function authenticationMethodOf(string $clientId, ClientMetadata $metadata): ClientAuthenticationMethodInterface
    {
        $wired = $this->methods->clientAuthenticationMethods();

        return $this->named($clientId, 'token_endpoint_auth_method', $metadata, $wired, MethodNames::of($wired));
    }

    /**
     * The shape the client registers its access tokens in, among those the provider is wired to write
     * (issue #239). A client that registers none takes the first wired shape, as it takes the first wired
     * authentication method.
     */
    private function accessTokenShape(string $clientId, ClientMetadata $metadata): AccessTokenShapeInterface
    {
        $wired = $this->shapes->servedAccessTokenShapes();

        return $this->named($clientId, 'access_token_format', $metadata, $wired, ShapeNames::of($wired));
    }

    /**
     * One of the things the provider is wired with, picked by the name the client registered, or the
     * first of them when the client registered none. Written once for the two options that read a wired
     * list this way, so that they cannot take a name, take a default or refuse differently; the names
     * are read from the things themselves and never written again here.
     *
     * @template T of object
     *
     * @param non-empty-list<T> $wired
     * @param non-empty-list<string> $names what each of them calls itself, in the same order
     *
     * @throws UnreadableClientMetadataException when the client registered a name nothing is wired with
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
     * The grants the client registers, among those the provider serves (issue #98). A grant that spends a
     * refresh token is worth nothing without one that issues it, so a registration that names the first and
     * none of the second is refused here too, where the two lists meet; which grants those are, the wired
     * grants say themselves and this reads nowhere else.
     *
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
     * What a client's registration must carry beside the grants it names, and what it must not, read where
     * the registration meets the wiring because only the wiring says what a grant does (issue #98).
     *
     * A grant whose flow sends the user's browser back to the client is spent against a redirect URI, so a
     * client registered for one registers at least one (RFC 6749 §3.1.2.2); a client registered for none
     * sends nobody anywhere and registers none, a URI nothing can redirect to being a promise the provider
     * would keep for nobody. The response types it registers answer the same question from the other side
     * (OIDC Registration §2), so a client that asks for a code and registers no grant that answers with one,
     * or the other way round, is refused rather than believed by halves. A grant served only to a client
     * that authenticates itself, a grant a client uses for itself (RFC 6749 §4.4) among them, is refused to a
     * public client here rather than at its first request (RFC 6749 §2.1), and a client using a grant for
     * itself is named in the "sub" of the tokens it gets, so an identifier no subject can be is refused with
     * it.
     *
     * @param list<GrantTypeName> $registered
     * @param list<RedirectUri> $redirectUris
     * @param list<string> $responseTypes empty for a client that registered none, which RFC 7591 §2 reads as the one this provider answers with
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
            // A client that registers no grant at all is refused by the registration itself, which needs
            // nothing of the wiring to say so
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
            // RFC 8693 §4.1, §4.4: the client is named where a subject is expected, in the "act" of the token
            // it receives and in the comparison a "may_act" is read for, so an identifier a subject cannot be
            // is refused here rather than at the first exchange
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
     * RFC 8693 §4.1, §4.4: the identifier of a client that is named where a subject is expected.
     *
     * @throws UnreadableClientMetadataException when no subject can be that identifier
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
     * RFC 8693 §2.1: what this client may do at the exchange, as a closed declaration and never a parameter of
     * a request. The types it may present are among the ones the provider is wired to read, so a type nothing
     * reads is refused rather than believed at the first request, and a type the provider gains is a class wired
     * beside the others with nothing here edited.
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
     * RFC 8693 §4.4: who may act for the subject of a token issued to this client, written on every token it
     * receives and compared with whoever asks to exchange one. Absent, the token says nothing and what decides
     * is the registration of the client that asks.
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
     * What names the client in the certificate it presents (RFC 8705 §2.1.2): one of the five keys, and
     * one only. A distinguished name is written back by the reader that will read the one of the
     * certificate, so that the registration is kept in the form the comparison will be made in and a
     * name that is not a distinguished name is refused rather than compared with nothing.
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
     * What the client registered in "request_object_signing_alg" (OIDC Registration §2), among the
     * algorithms the provider is wired with, plus the one value that is not an algorithm: "none", the
     * named exception of decision 0006, which is registered here and nowhere else. A client that
     * registers nothing has its request objects read under any algorithm the provider verifies, and
     * never unsigned.
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
     * The JWK Set a client publishes inline (RFC 7591 §2), read as the document it is.
     *
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
     * CIBA Core §4, §7.1: the mode this client registered, among the ones the provider is wired with.
     * There is no default and no first wired one taken: a client that registers nothing here is a client
     * of another flow, and it is refused at the endpoint of this one rather than served a mode nobody
     * asked for.
     *
     * @throws UnreadableClientMetadataException when the client registers a name nothing is wired with
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
     * RFC 8707 §2: the resources this client may ask a token for, each an absolute URI.
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
     * The redirection URIs of one of the two members that carry them (RFC 6749 §3.1.2, RP-Initiated Logout
     * §2), refused with the code RFC 7591 §3.2.2 reserves for them: a fragment, credentials, a scheme of its
     * own or plain HTTP on a name are all a redirect URI that is not one.
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
     * The URLs a request object of the client is read back from (OIDC Registration §2 "request_uris"), each
     * of the kind that may carry the fragment OIDC Core §6.2 defines (RequestUri).
     *
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
     * A URI the provider calls, loads or shows: where a logout token goes (Back-Channel Logout 1.0 §2.2),
     * what the logout page frames (Front-Channel Logout 1.0 §3), where the keys of the client are read back
     * from, and every page a user is shown about the client. Read and validated as every other URI a client
     * registers, which is what refuses a logo served in plain HTTP on a name.
     *
     * @throws UnreadableClientMetadataException
     */
    private function clientUri(string $clientId, string $option, ClientMetadata $metadata): ?ClientUri
    {
        $uri = $this->text($clientId, $option, $metadata);

        return $uri === null ? null : self::uri($uri, $option, $metadata->sourceOf($option));
    }

    /**
     * Where a third party has this provider begin a login at the client (OIDC Core §4), the one member
     * OIDC Registration §2 holds to "https" whatever the host, and a kind of its own for that reason
     * (InitiateLoginUri).
     *
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
     * An option a client registers as text, read once for every one of them, so that a value of another
     * kind is refused the same way wherever it was written.
     *
     * @throws UnreadableClientMetadataException
     *
     * @return string|null null when no source of the registration carries it
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
     * RFC 9396 §11 "authorization_details_types": the types of authorization detail this client may ask
     * for, among the ones the provider is wired with. A name nothing serves is refused rather than believed
     * at the first request that uses it, as a grant name and a token shape are.
     *
     * @throws UnreadableClientMetadataException when a name is not one of the wired types
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
     * A client registered a name the provider is not wired with. Nothing upstream can know that list, so the
     * refusal carries it, and it is read from the wiring wherever the name came from.
     *
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

    /**
     * What a value object of the domain says about itself, kept word for word: a URI, a scope or a set of
     * keys refuses itself in the terms a deployment reads at its boot and a client reads in its
     * "error_description", and this only says which member carried it and where that member came from.
     */
    private static function keeping(
        InvalidArgumentException $previous,
        ?string $member = null,
        ?string $source = null,
    ): InvalidClientMetadataException {
        return new InvalidClientMetadataException($member, $source, $previous->getMessage(), $previous);
    }
}

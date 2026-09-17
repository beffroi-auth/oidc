<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use function array_is_list;
use function array_keys;
use function array_map;
use DateTimeImmutable;
use function explode;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Exception\InvalidJwsException;
use Heidi\Core\Port\JwsVerifierInterface;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\VerifiedAccessToken;
use Heidi\Oidc\Exception\InvalidArgumentException as OidcInvalidArgumentException;
use Heidi\Oidc\Exception\InvalidTokenException;
use Heidi\Oidc\Port\AccessTokenRepositoryInterface;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use Heidi\Oidc\Port\SubjectIdentifierResolverInterface;
use function in_array;
use function is_array;
use function is_int;
use function is_string;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use JsonException;
use SensitiveParameter;
use function str_contains;
use Symfony\Component\Uid\Uuid;

/**
 * Verifies an access token this provider issued, in either of its shapes (architecture §4.6).
 *
 * A self-contained token is verified the way RFC 9068 §4 tells a resource server to: the signature
 * against the published keys of the tenant, the "typ" header equal to "at+jwt" so that an ID token of the
 * same issuer never passes for one, "iss" equal to the issuer, "exp" still ahead, and "aud" naming the
 * client the token was issued to ("client_id"), which must be a client the tenant knows: the provider
 * issues its access tokens to the client alone until a "resource" parameter says otherwise (RFC 8707,
 * later), and a token minted for another audience is not one of its own resources' tokens. Every claim
 * the issuer writes is read strictly; a payload that lacks one was not written here.
 *
 * An opaque token is a lookup of the record the repository keeps under its hash: the record must belong
 * to the tenant, not be expired, and its session must not have ended; a revoked token has no record
 * any more and is refused as unknown. A token with a dot is a JWS
 * (RFC 7515 §7.1); one without is an opaque value (StoredAccessToken::generate() writes none), so the
 * shape is told from the token itself and never from a hint.
 *
 * Neither path asks whether the grant is still alive: a resource server that holds only a JWT and the
 * keys cannot, and the provider's own resources do it once, in AccessTokenInspector.
 *
 * Everything that fails is invalid_token (RFC 6750 §3.1), with one description for whatever is not an
 * access token of this provider, another for one that merely expired, because a client that can refresh
 * should know that this is what to do, and a third for one whose session ended, which a refresh will
 * not cure either.
 */
final readonly class AccessTokenVerifier
{
    private const string NOT_ISSUED_HERE = 'The access token is not an access token issued by this provider.';

    private const string EXPIRED = 'The access token expired.';

    private const string REVOKED = 'The access token was revoked.';

    /**
     * An access token payload is a flat object whose deepest members are lists of strings ("amr",
     * "userinfo_claims"); anything deeper was not issued here.
     */
    private const int MAX_DEPTH = 3;

    public function __construct(
        private JwsVerifierInterface $verifier,
        private ClientRepositoryInterface $clients,
        private AccessTokenRepositoryInterface $storedTokens,
        private SubjectIdentifierResolverInterface $subjects,
    ) {
    }

    /**
     * @throws InvalidTokenException
     */
    public function verify(Tenant $tenant, #[SensitiveParameter] string $accessToken, DateTimeImmutable $now): VerifiedAccessToken
    {
        if (str_contains($accessToken, '.')) {
            return $this->verifyJwt($tenant, $accessToken, $now);
        }

        return $this->verifyOpaque($tenant, $accessToken, $now);
    }

    /**
     * @throws InvalidTokenException
     */
    private function verifyOpaque(Tenant $tenant, #[SensitiveParameter] string $accessToken, DateTimeImmutable $now): VerifiedAccessToken
    {
        $token = $this->storedTokens->find($accessToken);
        if ($token === null || ! $token->tenant->equals($tenant)) {
            throw new InvalidTokenException(self::NOT_ISSUED_HERE);
        }
        if ($token->session->hasEnded()) {
            throw new InvalidTokenException(self::REVOKED);
        }
        if ($token->isExpired($now)) {
            throw new InvalidTokenException(self::EXPIRED);
        }
        $requested = $token->claimsRequest === null ? [] : array_keys($token->claimsRequest->userinfo);

        return new VerifiedAccessToken(
            $token->client,
            $this->subjects->resolve($token->session->user, $token->client),
            $token->session->id,
            $token->grantId,
            $token->scopes,
            $requested,
            $token->authenticatedAt,
            $token->authenticationMethods,
            $token->authenticationContextClass,
            $token->issuedAt,
            $token->expiresAt,
        );
    }

    /**
     * @throws InvalidTokenException
     */
    private function verifyJwt(Tenant $tenant, #[SensitiveParameter] string $accessToken, DateTimeImmutable $now): VerifiedAccessToken
    {
        try {
            $jws = $this->verifier->verify($tenant, $accessToken);
            $claims = self::decode($jws->payload);
        } catch (InvalidJwsException|JsonException $exception) {
            throw new InvalidTokenException(self::NOT_ISSUED_HERE, $exception);
        }
        if (($jws->protectedHeader['typ'] ?? null) !== JwtAccessTokenIssuer::TYPE) {
            throw new InvalidTokenException(self::NOT_ISSUED_HERE);
        }
        if (($claims['iss'] ?? null) !== (string) $tenant->issuer) {
            throw new InvalidTokenException(self::NOT_ISSUED_HERE);
        }
        $exp = $claims['exp'] ?? null;
        $iat = $claims['iat'] ?? null;
        $authTime = $claims['auth_time'] ?? null;
        if (! is_int($exp) || ! is_int($iat) || ! is_int($authTime) || $exp <= $iat) {
            throw new InvalidTokenException(self::NOT_ISSUED_HERE);
        }
        // RFC 7519 §4.1.4: the current time must be before "exp"; no leeway, the clocks are the provider's own
        if ($exp <= $now->getTimestamp()) {
            throw new InvalidTokenException(self::EXPIRED);
        }
        $clientId = $claims['client_id'] ?? null;
        $client = is_string($clientId) ? $this->clients->findByClientId($tenant, $clientId) : null;
        if ($client === null || ! self::isAudience($claims['aud'] ?? null, $client->clientId)) {
            throw new InvalidTokenException(self::NOT_ISSUED_HERE);
        }
        $sub = $claims['sub'] ?? null;
        $sid = $claims['sid'] ?? null;
        $grantId = $claims[JwtAccessTokenIssuer::GRANT_ID] ?? null;
        $acr = $claims['acr'] ?? null;
        if (! is_string($sub) || ! is_string($sid) || ! Uuid::isValid($sid) || ! is_string($grantId) || ! Uuid::isValid($grantId) || ! is_string($acr) || $acr === '') {
            throw new InvalidTokenException(self::NOT_ISSUED_HERE);
        }
        try {
            $subject = new Subject($sub);
            $scopes = self::scopes($claims['scope'] ?? null);
        } catch (InvalidArgumentException|OidcInvalidArgumentException $exception) {
            throw new InvalidTokenException(self::NOT_ISSUED_HERE, $exception);
        }

        return new VerifiedAccessToken(
            $client,
            $subject,
            Uuid::fromString($sid),
            Uuid::fromString($grantId),
            $scopes,
            self::stringList($claims[JwtAccessTokenIssuer::USERINFO_CLAIMS] ?? []),
            new DateTimeImmutable('@' . $authTime),
            self::stringList($claims['amr'] ?? null),
            $acr,
            new DateTimeImmutable('@' . $iat),
            new DateTimeImmutable('@' . $exp),
        );
    }

    /**
     * The claims of a JWT are a JSON object (RFC 7519 §3); a list has no "iss" and is refused further
     * down like any other.
     *
     * @throws JsonException
     * @return array<array-key, mixed>
     */
    private static function decode(string $payload): array
    {
        $claims = json_decode($payload, true, self::MAX_DEPTH, JSON_THROW_ON_ERROR);
        if (! is_array($claims)) {
            throw new InvalidTokenException(self::NOT_ISSUED_HERE);
        }

        return $claims;
    }

    /**
     * RFC 7519 §4.1.3 "aud": a single string or a list of strings.
     */
    private static function isAudience(mixed $aud, string $clientId): bool
    {
        if (is_string($aud)) {
            return $aud === $clientId;
        }

        return is_array($aud) && array_is_list($aud) && in_array($clientId, $aud, true);
    }

    /**
     * RFC 9068 §2.2.3, RFC 8693 §4.2: "scope" is a string of scope tokens separated by single spaces;
     * absent, the token carries none.
     *
     * @throws OidcInvalidArgumentException when a scope token is not one
     * @return list<Scope>
     */
    private static function scopes(mixed $scope): array
    {
        if ($scope === null) {
            return [];
        }
        if (! is_string($scope)) {
            throw new OidcInvalidArgumentException('The scope claim is not a string.');
        }

        return array_map(static fn (string $token): Scope => new Scope($token), explode(' ', $scope));
    }

    /**
     * A list of non-empty strings, as "amr" (RFC 8176) and "userinfo_claims" (architecture §4.6) are
     * written; "userinfo_claims" is absent when the client asked for no claim by name, "amr" never is.
     *
     * @throws InvalidTokenException
     * @return list<string>
     */
    private static function stringList(mixed $values): array
    {
        if (! is_array($values) || ! array_is_list($values)) {
            throw new InvalidTokenException(self::NOT_ISSUED_HERE);
        }
        foreach ($values as $value) {
            if (! is_string($value) || $value === '') {
                throw new InvalidTokenException(self::NOT_ISSUED_HERE);
            }
        }

        return $values;
    }
}

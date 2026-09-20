<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use function array_is_list;
use function array_keys;
use DateTimeImmutable;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Exception\InvalidJwsException;
use Heidi\Core\Port\JwsVerifierInterface;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
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
 * Verifies an access token of this provider in either shape (architecture §4.6): a JWS the way RFC 9068
 * §4 tells a resource server to, every claim the issuer writes read strictly; an opaque one by the record
 * kept under its hash. The shape is told from the token itself (a dot), never from a hint. Whether the
 * grant is still alive is asked once, in AccessTokenInspector. Every failure is invalid_token (RFC 6750 §3.1).
 */
final readonly class AccessTokenVerifier
{
    private const string NOT_ISSUED_HERE = 'The access token is not an access token issued by this provider.';

    private const string EXPIRED = 'The access token expired.';

    private const string REVOKED = 'The access token was revoked.';

    /**
     * Deeper than the lists of strings ("amr", "userinfo_claims") was not issued here.
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
            $token->authentication,
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
        if (! is_int($exp) || ! is_int($iat) || $exp <= $iat) {
            throw new InvalidTokenException(self::NOT_ISSUED_HERE);
        }
        // RFC 7519 §4.1.4, no leeway: the clocks are the provider's own
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
        if (! is_string($sub) || ! is_string($sid) || ! Uuid::isValid($sid) || ! is_string($grantId) || ! Uuid::isValid($grantId)) {
            throw new InvalidTokenException(self::NOT_ISSUED_HERE);
        }
        try {
            $subject = new Subject($sub);
            $scopes = self::scopes($claims['scope'] ?? null);
            $authentication = AuthenticationSnapshot::fromClaims($claims);
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
            $authentication,
            new DateTimeImmutable('@' . $iat),
            new DateTimeImmutable('@' . $exp),
        );
    }

    /**
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
     * RFC 9068 §2.2.3, RFC 8693 §4.2; absent, the token carries none.
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

        return Scope::parseList($scope);
    }

    /**
     * As "userinfo_claims" (architecture §4.6) is written.
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

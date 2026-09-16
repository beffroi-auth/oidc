<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use function array_is_list;
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
use Heidi\Oidc\Port\ClientRepositoryInterface;
use function in_array;
use function is_array;
use function is_int;
use function is_string;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use JsonException;
use Symfony\Component\Uid\Uuid;

/**
 * Verifies an access token this provider issued, the way RFC 9068 §4 tells a resource server to: the
 * signature against the published keys of the tenant, the "typ" header equal to "at+jwt" so that an ID
 * token of the same issuer never passes for one, "iss" equal to the issuer, "exp" still ahead, and "aud"
 * naming the client the token was issued to ("client_id"), which must be a client the tenant knows: the
 * provider issues its access tokens to the client alone until a "resource" parameter says otherwise
 * (RFC 8707, later), and a token minted for another audience is not one of its own resources' tokens.
 *
 * "grant_id" is read too, the grant the token descends from: this verifier does not ask whether that
 * grant is still alive, a resource server that holds only the token and the keys cannot; the provider's
 * own UserInfo does, because it already knows where the grants live.
 *
 * Everything that fails is invalid_token (RFC 6750 §3.1), with one description for whatever is not an
 * access token of this provider and another for one that merely expired, because a client that can
 * refresh should know that this is what to do.
 */
final readonly class AccessTokenVerifier
{
    private const string NOT_ISSUED_HERE = 'The access token is not an access token issued by this provider.';

    private const string EXPIRED = 'The access token expired.';

    /**
     * An access token payload is a flat object whose deepest members are lists of strings ("amr",
     * "userinfo_claims"); anything deeper was not issued here.
     */
    private const int MAX_DEPTH = 3;

    public function __construct(
        private JwsVerifierInterface $verifier,
        private ClientRepositoryInterface $clients,
    ) {
    }

    /**
     * @throws InvalidTokenException
     */
    public function verify(Tenant $tenant, string $accessToken, DateTimeImmutable $now): VerifiedAccessToken
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
        if (! is_int($exp)) {
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
        $grantId = $claims[JwtAccessTokenIssuer::GRANT_ID] ?? null;
        if (! is_string($sub) || ! is_string($grantId) || ! Uuid::isValid($grantId)) {
            throw new InvalidTokenException(self::NOT_ISSUED_HERE);
        }
        try {
            $subject = new Subject($sub);
            $scopes = self::scopes($claims['scope'] ?? null);
        } catch (InvalidArgumentException|OidcInvalidArgumentException $exception) {
            throw new InvalidTokenException(self::NOT_ISSUED_HERE, $exception);
        }

        return new VerifiedAccessToken($client, $subject, Uuid::fromString($grantId), $scopes, self::userinfoClaims($claims[JwtAccessTokenIssuer::USERINFO_CLAIMS] ?? null), new DateTimeImmutable('@' . $exp));
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
     * Architecture §4.6: a list of claim names; absent, the client asked for none by name.
     *
     * @throws InvalidTokenException
     * @return list<string>
     */
    private static function userinfoClaims(mixed $names): array
    {
        if ($names === null) {
            return [];
        }
        if (! is_array($names) || ! array_is_list($names)) {
            throw new InvalidTokenException(self::NOT_ISSUED_HERE);
        }
        foreach ($names as $name) {
            if (! is_string($name) || $name === '') {
                throw new InvalidTokenException(self::NOT_ISSUED_HERE);
            }
        }

        return $names;
    }
}

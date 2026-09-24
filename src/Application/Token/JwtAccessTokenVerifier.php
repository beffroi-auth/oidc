<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use function array_is_list;
use DateTimeImmutable;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Exception\InvalidJwsException;
use Heidi\Core\Port\JwsVerifierInterface;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Token\VerifiedAccessToken;
use Heidi\Oidc\Exception\InvalidArgumentException as OidcInvalidArgumentException;
use Heidi\Oidc\Exception\InvalidTokenException;
use Heidi\Oidc\Port\AccessTokenVerifierInterface;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use Heidi\Oidc\Port\ConfirmationReaderInterface;
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
 * Reads back a self-contained access token (RFC 9068 §4), the counterpart of JwtAccessTokenIssuer: every
 * claim the issuer wrote, read strictly, and nothing believed that the signature does not cover. A token
 * of this shape carries what it says, so it expires on its own and no endpoint takes it back
 * (RFC 7009 §2.2.1).
 */
final readonly class JwtAccessTokenVerifier implements AccessTokenVerifierInterface
{
    /**
     * Deeper than the lists of strings ("amr", "userinfo_claims") was not issued here.
     */
    private const int MAX_DEPTH = 3;

    public function __construct(
        private JwsVerifierInterface $verifier,
        private ClientRepositoryInterface $clients,
        private ConfirmationReaderInterface $confirmations,
    ) {
    }

    /**
     * RFC 7515 §3.1: a compact serialization is three parts separated by dots, which nothing this
     * provider draws for an opaque token ever contains.
     */
    public function recognises(#[SensitiveParameter] string $accessToken): bool
    {
        return str_contains($accessToken, '.');
    }

    public function expiresOnItsOwn(): bool
    {
        return true;
    }

    public function verify(Tenant $tenant, #[SensitiveParameter] string $accessToken, DateTimeImmutable $now): VerifiedAccessToken
    {
        try {
            $jws = $this->verifier->verify($tenant, $accessToken);
            $claims = self::decode($jws->payload);
        } catch (InvalidJwsException|JsonException $exception) {
            throw InvalidTokenException::notIssuedHere($exception);
        }
        if (($jws->protectedHeader['typ'] ?? null) !== JwtAccessTokenIssuer::TYPE) {
            throw InvalidTokenException::notIssuedHere();
        }
        if (($claims['iss'] ?? null) !== (string) $tenant->issuer) {
            throw InvalidTokenException::notIssuedHere();
        }
        $exp = $claims['exp'] ?? null;
        $iat = $claims['iat'] ?? null;
        if (! is_int($exp) || ! is_int($iat) || $exp <= $iat) {
            throw InvalidTokenException::notIssuedHere();
        }
        // RFC 7519 §4.1.4, no leeway: the clocks are the provider's own
        if ($exp <= $now->getTimestamp()) {
            throw InvalidTokenException::expired();
        }
        $clientId = $claims['client_id'] ?? null;
        $client = is_string($clientId) ? $this->clients->findByClientId($tenant, $clientId) : null;
        if ($client === null || ! self::isAudience($claims['aud'] ?? null, $client->registration->clientId)) {
            throw InvalidTokenException::notIssuedHere();
        }
        $sub = $claims['sub'] ?? null;
        $sid = $claims['sid'] ?? null;
        $grantId = $claims[JwtAccessTokenIssuer::GRANT_ID] ?? null;
        if (! is_string($sub) || ! is_string($sid) || ! Uuid::isValid($sid) || ! is_string($grantId) || ! Uuid::isValid($grantId)) {
            throw InvalidTokenException::notIssuedHere();
        }
        try {
            $subject = new Subject($sub);
            $scopes = self::scopes($claims['scope'] ?? null);
            $authentication = AuthenticationSnapshot::fromClaims($claims);
            $confirmation = $this->confirmations->fromClaims($claims);
        } catch (InvalidArgumentException|OidcInvalidArgumentException $exception) {
            throw InvalidTokenException::notIssuedHere($exception);
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
            $confirmation,
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
            throw InvalidTokenException::notIssuedHere();
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
     */
    private static function scopes(mixed $scope): ?Scopes
    {
        if ($scope === null) {
            return null;
        }
        if (! is_string($scope)) {
            throw new OidcInvalidArgumentException('The scope claim is not a string.');
        }

        return Scopes::parse($scope);
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
            throw InvalidTokenException::notIssuedHere();
        }
        foreach ($values as $value) {
            if (! is_string($value) || $value === '') {
                throw InvalidTokenException::notIssuedHere();
            }
        }

        return $values;
    }
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use function array_is_list;
use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\InvalidJwsException;
use Beffroi\Core\Port\JwsVerifierInterface;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Exchange\Actor;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\TokenAudience;
use Beffroi\Oidc\Domain\Token\TokenSignIn;
use Beffroi\Oidc\Domain\Token\VerifiedAccessToken;
use Beffroi\Oidc\Exception\InvalidArgumentException as OidcInvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidTokenException;
use Beffroi\Oidc\Port\AccessTokenVerifierInterface;
use Beffroi\Oidc\Port\AuthorizationDetailsReaderInterface;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use Beffroi\Oidc\Port\ConfirmationReaderInterface;
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
 *
 * A token that names a sign-in says all of it, and a token that names none says nothing of one: a "sid"
 * without the claims of its session, or those claims without a "sid", is not what this provider writes
 * and is refused here (RFC 6749 §4.4).
 *
 * The chain of actors is read as it was written, the most recent actor outermost (RFC 8693 §4.1), so that a
 * delegation stays a delegation on the way back and a resource server of the provider reads what a resource
 * server verifying offline reads.
 */
final readonly class JwtAccessTokenVerifier implements AccessTokenVerifierInterface
{
    /**
     * Deeper than the lists of strings ("amr", "userinfo_claims"), a chain of actors nested a few
     * exchanges deep ("act", RFC 8693 §4.1) and an "authorization_details" as deep as the parameter it
     * came from (RFC 9396 §2, §7) was not issued here.
     */
    private const int MAX_DEPTH = 7;

    public function __construct(
        private JwsVerifierInterface $verifier,
        private ClientRepositoryInterface $clients,
        private ConfirmationReaderInterface $confirmations,
        private AuthorizationDetailsReaderInterface $authorizationDetailTypes,
    ) {
    }

    /**
     * The shape JwtAccessTokenIssuer writes, which a client registers by this name.
     */
    public function name(): string
    {
        return 'jwt';
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
        if ($client === null) {
            throw InvalidTokenException::notIssuedHere();
        }
        // RFC 8707 §2: the token is addressed to the resources it was asked for, or to the client when
        // it was asked for none; an "aud" this provider would never have written for this client is
        // refused before anything else the token says is believed
        try {
            $audience = TokenAudience::fromClaim($claims['aud'] ?? null);
        } catch (OidcInvalidArgumentException $exception) {
            throw InvalidTokenException::notIssuedHere($exception);
        }
        if (! $client->registration->mayBeAddressedTo($audience)) {
            throw InvalidTokenException::notIssuedHere();
        }
        $sub = $claims['sub'] ?? null;
        $grantId = $claims[JwtAccessTokenIssuer::GRANT_ID] ?? null;
        if (! is_string($sub) || ! is_string($grantId) || ! Uuid::isValid($grantId)) {
            throw InvalidTokenException::notIssuedHere();
        }
        try {
            $subject = new Subject($sub);
            $scopes = self::scopes($claims['scope'] ?? null);
            $signIn = self::signIn($claims);
            $confirmation = $this->confirmations->fromClaims($claims);
            $actor = isset($claims[JwtAccessTokenIssuer::ACTOR]) ? Actor::fromClaim($claims[JwtAccessTokenIssuer::ACTOR]) : null;
            $details = self::authorizationDetails($claims, $this->authorizationDetailTypes);
        } catch (InvalidArgumentException|OidcInvalidArgumentException $exception) {
            throw InvalidTokenException::notIssuedHere($exception);
        }

        return new VerifiedAccessToken(
            $client,
            $audience,
            $subject,
            Uuid::fromString($grantId),
            $scopes,
            $signIn,
            self::stringList($claims[JwtAccessTokenIssuer::USERINFO_CLAIMS] ?? []),
            new DateTimeImmutable('@' . $iat),
            new DateTimeImmutable('@' . $exp),
            $confirmation,
            $actor,
            $details,
        );
    }

    /**
     * RFC 9396 §7: what the token carries beyond its scopes, read back through the types the provider is
     * wired with, null when it carries none. A token naming a type this provider no longer serves is a
     * token it can no longer describe, and it is refused rather than described without the part that says
     * what it was for.
     *
     * @param array<array-key, mixed> $claims
     *
     * @throws OidcInvalidArgumentException when what the claim carries is not what this provider writes there
     */
    private static function authorizationDetails(array $claims, AuthorizationDetailsReaderInterface $types): ?AuthorizationDetails
    {
        $claim = $claims[JwtAccessTokenIssuer::AUTHORIZATION_DETAILS] ?? null;

        return $claim === null ? null : $types->fromClaim($claim);
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
     * The sign-in the token descends from, null when it names none, which is what a token a client holds
     * for itself looks like (RFC 6749 §4.4). A "sid" is answered for by the claims of its session and they
     * by it: half of a sign-in was not written here.
     *
     * @param array<array-key, mixed> $claims
     *
     * @throws InvalidTokenException
     * @throws OidcInvalidArgumentException when what the claims say of a session is not what one says
     */
    private static function signIn(array $claims): ?TokenSignIn
    {
        $sid = $claims['sid'] ?? null;
        if ($sid === null) {
            if (isset($claims['auth_time']) || isset($claims['acr']) || isset($claims['amr'])) {
                throw InvalidTokenException::notIssuedHere();
            }

            return null;
        }
        if (! is_string($sid) || ! Uuid::isValid($sid)) {
            throw InvalidTokenException::notIssuedHere();
        }

        return new TokenSignIn(Uuid::fromString($sid), AuthenticationSnapshot::fromClaims($claims));
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

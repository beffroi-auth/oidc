<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Introspection;

use function array_map;
use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Domain\Token\TokenResponse;
use Heidi\Oidc\Domain\Token\VerifiedAccessToken;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function implode;
use SensitiveParameter;

/**
 * The answer of the introspection endpoint (RFC 7662 §2.2): a JSON object whose "active" member is a
 * real boolean, alone when the token is not one the caller may honour, followed otherwise by what the
 * provider knows of the token: "scope", "client_id", "token_type", "exp", "iat", "sub", "aud", "iss", the
 * authentication the token stands on ("auth_time", "acr", "amr", the same members RFC 9068 §2.2.1 puts in
 * a JWT, so that a resource server learns the same from either shape), and the two private names the
 * provider's own tokens carry, "sid" and "grant_id" (architecture §4.6). An inactive token says nothing
 * else, whatever the reason (§2.2: "the introspection endpoint MUST NOT include any additional
 * information"): a caller must not learn from this endpoint that a token exists but belongs to another.
 *
 * When the caller asked for it (RFC 9701 §4), the same object travels as the "token_introspection" claim
 * of a JWT signed by the provider, with the media type of §5; the JSON members are kept so that the
 * integration can serve either.
 */
final readonly class IntrospectionResponse
{
    public const string CONTENT_TYPE = 'application/json';

    /**
     * RFC 9701 §5: the media type of a signed response, and the "typ" header of its JWT (RFC 7515 §4.1.9
     * lets the "application/" prefix go).
     */
    public const string JWT_CONTENT_TYPE = 'application/token-introspection+jwt';

    public const string JWT_TYPE = 'token-introspection+jwt';

    /**
     * RFC 7662 §2.2, RFC 6749 §5.1: the response is about a credential, nothing of it is cached.
     */
    public const array HEADERS = TokenResponse::HEADERS;

    /**
     * @param array<string, mixed> $members "active" first
     * @param string|null $jwt the signed form of the members, when the caller asked for one (RFC 9701)
     */
    private function __construct(
        public array $members,
        #[SensitiveParameter]
        public ?string $jwt,
    ) {
        if ($jwt === '') {
            throw new InvalidArgumentException('A signed introspection response is either absent or non-empty.');
        }
    }

    public static function inactive(): self
    {
        return new self([
            'active' => false,
        ], null);
    }

    /**
     * RFC 7662 §2.2, members in the order the section lists them, then the ones of the provider.
     */
    public static function active(VerifiedAccessToken $token, Issuer $issuer): self
    {
        return new self([
            'active' => true,
            'scope' => implode(' ', array_map(static fn (Scope $scope): string => $scope->value, $token->scopes)),
            'client_id' => $token->client->clientId,
            'token_type' => TokenResponse::TOKEN_TYPE,
            'exp' => $token->expiresAt->getTimestamp(),
            'iat' => $token->issuedAt->getTimestamp(),
            'sub' => $token->subject->value,
            'aud' => $token->client->clientId,
            'iss' => $issuer->value,
            'auth_time' => $token->authenticatedAt->getTimestamp(),
            'acr' => $token->authenticationContextClass,
            'amr' => $token->authenticationMethods,
            'sid' => $token->sessionId->toRfc4122(),
            'grant_id' => $token->grantId->toRfc4122(),
        ], null);
    }

    /**
     * The same answer, signed (RFC 9701 §4): the integration serves the JWT with its media type.
     */
    public function signed(#[SensitiveParameter] string $jwt): self
    {
        return new self($this->members, $jwt);
    }

    public function isActive(): bool
    {
        return $this->members['active'] === true;
    }

    public function contentType(): string
    {
        return $this->jwt === null ? self::CONTENT_TYPE : self::JWT_CONTENT_TYPE;
    }

    /**
     * @return string the body as the caller reads it: the JSON object, or the compact JWS that wraps it
     */
    public function body(): string
    {
        return $this->jwt ?? JwtPayload::encode($this->members);
    }
}

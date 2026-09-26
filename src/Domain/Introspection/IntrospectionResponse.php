<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Introspection;

use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Domain\Token\TokenResponse;
use Heidi\Oidc\Domain\Token\VerifiedAccessToken;
use Heidi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;

/**
 * The answer of the introspection endpoint (RFC 7662 §2.2): "active" as a real boolean, alone when the
 * token is inactive, followed otherwise by the members of §2.2, those of RFC 9068 §2.2.1 and the private
 * ones of the provider (architecture §4.6). Signed on request (RFC 9701 §4).
 *
 * What a token says is what is rendered: a token a client holds for itself names that client in "sub" and
 * carries no "sid", no "auth_time", no "acr" and no "amr", because nobody signed in for it (RFC 6749 §4.4);
 * a token somebody holds for its subject renders who in "act" (RFC 8693 §4.1), and one nobody holds for
 * anybody renders no "act" at all, which is what tells a delegation from an impersonation (§1.3); a token of
 * a grant somebody agreed to renders the "authorization_details" they agreed to (RFC 9396 §9), and one
 * nobody agreed to renders none.
 */
final readonly class IntrospectionResponse
{
    public const string CONTENT_TYPE = 'application/json';

    /**
     * RFC 9701 §5; the "typ" header drops the "application/" prefix (RFC 7515 §4.1.9).
     */
    public const string JWT_CONTENT_TYPE = 'application/token-introspection+jwt';

    public const string JWT_TYPE = 'token-introspection+jwt';

    /**
     * RFC 7662 §2.2, RFC 6749 §5.1: never cached.
     */
    public const array HEADERS = TokenResponse::HEADERS;

    /**
     * @param array<string, mixed> $members "active" first
     * @param string|null $jwt the signed form of the members (RFC 9701)
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
     * RFC 7662 §2.2, in the order of the section, then the ones of the provider.
     */
    public static function active(VerifiedAccessToken $token, Issuer $issuer): self
    {
        return new self(
            [
                'active' => true,
                'scope' => (string) $token->scopes,
                'client_id' => $token->client->registration->clientId,
                'token_type' => $token->confirmation?->scheme() ?? TokenResponse::BEARER,
                'exp' => $token->expiresAt->getTimestamp(),
                'iat' => $token->issuedAt->getTimestamp(),
                'sub' => $token->subject->value,
                'aud' => $token->audience->claim(),
                'iss' => $issuer->value,
                // A token a client holds for itself descends from no sign-in, so it renders nothing of
                // one rather than rendering it empty (RFC 6749 §4.4)
                ...($token->signIn?->toClaims() ?? []),
                'grant_id' => $token->grantId->toRfc4122(),
                // RFC 8693 §4.1: who holds the token on behalf of its subject, the most recent actor
                // outermost, which is what a resource server reads to know through whom it was reached
                ...(
                    $token->actor === null
                        ? []
                        : [
                            'act' => $token->actor->toClaim(),
                        ]
                ),
                // RFC 9396 §9: what the token is good for beyond its scopes, as the resource server that
                // has to honour it reads it, the same array the self-contained shape carries
                ...(
                    $token->authorizationDetails === null
                        ? []
                        : [
                            'authorization_details' => $token->authorizationDetails->toClaim(),
                        ]
                ),
                // RFC 8705 §3.2: a resource server reads here what it must ask the caller to present again
                ...($token->confirmation?->toClaims() ?? []),
            ],
            null,
        );
    }

    /**
     * RFC 9701 §4.
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

    public function body(): string
    {
        return $this->jwt ?? JwtPayload::encode($this->members);
    }
}

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
 * The answer of the introspection endpoint (RFC 7662 §2.2): "active" as a real boolean, alone when the
 * token is inactive, followed otherwise by the members of §2.2, those of RFC 9068 §2.2.1 and the private
 * ones of the provider (architecture §4.6). Signed on request (RFC 9701 §4).
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
        return new self([
            'active' => true,
            'scope' => implode(' ', array_map(static fn (Scope $scope): string => $scope->value, $token->scopes)),
            'client_id' => $token->client->clientId,
            'token_type' => $token->confirmation?->scheme() ?? TokenResponse::BEARER,
            'exp' => $token->expiresAt->getTimestamp(),
            'iat' => $token->issuedAt->getTimestamp(),
            'sub' => $token->subject->value,
            'aud' => $token->client->clientId,
            'iss' => $issuer->value,
            ...$token->authentication->toClaims(),
            'sid' => $token->sessionId->toRfc4122(),
            'grant_id' => $token->grantId->toRfc4122(),
            // RFC 8705 §3.2: a resource server reads here what it must ask the caller to present again
            ...($token->confirmation?->toClaims() ?? []),
        ], null);
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

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Introspection;

use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Oidc\Domain\Token\JwtPayload;
use Beffroi\Oidc\Domain\Token\TokenResponse;
use Beffroi\Oidc\Domain\Token\VerifiedAccessToken;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;

/**
 * RFC 7662 §2.2, RFC 9701 §4
 */
final readonly class IntrospectionResponse
{
    public const string CONTENT_TYPE = 'application/json';

    /**
     * RFC 9701 §5
     */
    public const string JWT_CONTENT_TYPE = 'application/token-introspection+jwt';

    public const string JWT_TYPE = 'token-introspection+jwt';

    /**
     * RFC 7662 §2.2, RFC 6749 §5.1
     */
    public const array HEADERS = TokenResponse::HEADERS;

    /**
     * @param array<string, mixed> $members "active" first
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
     * RFC 7662 §2.2
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
                ...($token->signIn?->toClaims() ?? []),
                'grant_id' => $token->grantId->toRfc4122(),
                ...(
                    $token->actor === null
                        ? []
                        : [
                            'act' => $token->actor->toClaim(),
                        ]
                ),
                ...(
                    $token->authorizationDetails === null
                        ? []
                        : [
                            'authorization_details' => $token->authorizationDetails->toClaim(),
                        ]
                ),
                ...($token->confirmation?->toClaims() ?? []),
            ],
            null,
        );
    }

    /**
     * RFC 9701 §4
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

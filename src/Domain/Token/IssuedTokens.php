<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;

final readonly class IssuedTokens
{
    public function __construct(
        public AuthorizationInterface $authorization,
        public AccessToken $accessToken,
        #[SensitiveParameter]
        public ?string $idToken,
        public ?IssuedRefreshToken $refreshToken,
        public ?TokenTypeIdentifier $issuedTokenType = null,
    ) {
        if ($idToken === '') {
            throw new InvalidArgumentException('An ID token is either absent or non-empty.');
        }
    }

    /**
     * RFC 8693 §2.2.1
     */
    public function withIssuedTokenType(TokenTypeIdentifier $issuedTokenType): self
    {
        return new self($this->authorization, $this->accessToken, $this->idToken, $this->refreshToken, $issuedTokenType);
    }

    public function toResponse(): TokenResponse
    {
        return new TokenResponse(
            $this->accessToken->value,
            $this->accessToken->expiresIn(),
            $this->refreshToken?->value,
            $this->idToken,
            $this->authorization->scopes,
            $this->authorization->confirmation?->scheme() ?? TokenResponse::BEARER,
            $this->issuedTokenType,
            CarriedAuthorizationDetails::of($this->authorization),
        );
    }
}

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use Heidi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Heidi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;

/**
 * What one token request produced (architecture §4.5): the access token, and whatever else the
 * authorization it spends entitled the client to.
 *
 * A grant that turns one token into another says the type of the token it issued (RFC 8693 §2.2.1), which is
 * the one thing a response of an exchange carries that no other response does; the grant says it because it
 * is the one that knows what it was asked for.
 */
final readonly class IssuedTokens
{
    /**
     * @param TokenTypeIdentifier|null $issuedTokenType the type of the access token, for a grant that has one to name (RFC 8693 §2.2.1)
     */
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
     * The same tokens, answered as the response of an exchange (RFC 8693 §2.2.1): the grant that exchanged
     * them names the type it issued, which is what a client reads to know what it was handed.
     */
    public function withIssuedTokenType(TokenTypeIdentifier $issuedTokenType): self
    {
        return new self($this->authorization, $this->accessToken, $this->idToken, $this->refreshToken, $issuedTokenType);
    }

    /**
     * RFC 6749 §5.1, OIDC Core §3.1.3.3.
     */
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
        );
    }
}

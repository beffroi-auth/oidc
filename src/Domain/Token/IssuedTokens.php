<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use Heidi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;

/**
 * What one token request produced (architecture §4.5): the access token, and whatever else the
 * authorization it spends entitled the client to.
 */
final readonly class IssuedTokens
{
    public function __construct(
        public AuthorizationInterface $authorization,
        public AccessToken $accessToken,
        #[SensitiveParameter]
        public ?string $idToken,
        public ?IssuedRefreshToken $refreshToken,
    ) {
        if ($idToken === '') {
            throw new InvalidArgumentException('An ID token is either absent or non-empty.');
        }
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
        );
    }
}

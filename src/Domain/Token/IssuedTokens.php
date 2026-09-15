<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use Heidi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;

/**
 * What one token request produced (architecture §4.5): the access token, the ID token when "openid" was
 * among the scopes, and the refresh token if one was due. The response is built from it; the events are
 * not, because they must not carry the values.
 */
final readonly class IssuedTokens
{
    public function __construct(
        public GrantedAuthorization $authorization,
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
        return new TokenResponse($this->accessToken->value, $this->accessToken->expiresIn(), $this->refreshToken?->value, $this->idToken, $this->authorization->scopes);
    }
}

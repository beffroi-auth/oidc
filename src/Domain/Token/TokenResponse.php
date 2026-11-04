<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;

/**
 * RFC 6749 §5.1, OIDC Core §3.1.3.3, RFC 8693 §2.2.1, RFC 9396 §7
 */
final readonly class TokenResponse
{
    /**
     * RFC 6749 §5.1, RFC 6750 §6.1; a token bound to a certificate is a bearer token too (RFC 8705 §3)
     */
    public const string BEARER = 'Bearer';

    public const string CONTENT_TYPE = 'application/json';

    /**
     * RFC 6749 §5.1, §5.2
     */
    public const array HEADERS = [
        'Cache-Control' => 'no-store',
        'Pragma' => 'no-cache',
    ];

    /**
     * @param positive-int $expiresIn
     */
    public function __construct(
        #[SensitiveParameter]
        public string $accessToken,
        public int $expiresIn,
        #[SensitiveParameter]
        public ?string $refreshToken,
        #[SensitiveParameter]
        public ?string $idToken,
        public Scopes $scopes,
        public string $tokenType = self::BEARER,
        public ?TokenTypeIdentifier $issuedTokenType = null,
        public ?AuthorizationDetails $authorizationDetails = null,
    ) {
        if ($accessToken === '') {
            throw new InvalidArgumentException('A token response carries an access token.');
        }
        if ($refreshToken === '' || $idToken === '') {
            throw new InvalidArgumentException('A refresh token or an ID token is either absent or non-empty.');
        }
    }

    /**
     * @return non-empty-array<string, string|positive-int|non-empty-list<non-empty-array<string, mixed>>>
     */
    public function parameters(): array
    {
        $parameters = [
            'access_token' => $this->accessToken,
            'token_type' => $this->tokenType,
            'expires_in' => $this->expiresIn,
        ];
        if ($this->issuedTokenType !== null) {
            $parameters['issued_token_type'] = $this->issuedTokenType->value;
        }
        if ($this->refreshToken !== null) {
            $parameters['refresh_token'] = $this->refreshToken;
        }
        if ($this->idToken !== null) {
            $parameters['id_token'] = $this->idToken;
        }
        $parameters['scope'] = (string) $this->scopes;
        if ($this->authorizationDetails !== null) {
            $parameters['authorization_details'] = $this->authorizationDetails->toClaim();
        }

        return $parameters;
    }
}

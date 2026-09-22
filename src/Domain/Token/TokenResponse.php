<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function implode;
use SensitiveParameter;

/**
 * The successful answer of the token endpoint (RFC 6749 §5.1, OIDC Core §3.1.3.3); "scope" is always there.
 */
final readonly class TokenResponse
{
    /**
     * RFC 6749 §5.1, RFC 6750 §6.1: the type of a token whose holder is whoever presents it, and of one
     * the transport binds (RFC 8705 §3, which changes nothing to the way a client sends it).
     */
    public const string BEARER = 'Bearer';

    public const string CONTENT_TYPE = 'application/json';

    /**
     * RFC 6749 §5.1, for the errors of §5.2 as well.
     */
    public const array HEADERS = [
        'Cache-Control' => 'no-store',
        'Pragma' => 'no-cache',
    ];

    /**
     * @var non-empty-list<Scope>
     */
    public array $scopes;

    /**
     * @param positive-int $expiresIn
     * @param list<Scope> $scopes at least one
     * @param string $tokenType how the client presents the token it is handed (RFC 6749 §5.1), which is
     *                          what the binding of the token says and "Bearer" when it has none
     */
    public function __construct(
        #[SensitiveParameter]
        public string $accessToken,
        public int $expiresIn,
        #[SensitiveParameter]
        public ?string $refreshToken,
        #[SensitiveParameter]
        public ?string $idToken,
        array $scopes,
        public string $tokenType = self::BEARER,
    ) {
        if ($accessToken === '') {
            throw new InvalidArgumentException('A token response carries an access token.');
        }
        if ($refreshToken === '' || $idToken === '') {
            throw new InvalidArgumentException('A refresh token or an ID token is either absent or non-empty.');
        }
        if ($scopes === []) {
            throw new InvalidArgumentException('A token response names at least one scope.');
        }
        $this->scopes = $scopes;
    }

    /**
     * @return non-empty-array<string, string|positive-int>
     */
    public function parameters(): array
    {
        $parameters = [
            'access_token' => $this->accessToken,
            'token_type' => $this->tokenType,
            'expires_in' => $this->expiresIn,
        ];
        if ($this->refreshToken !== null) {
            $parameters['refresh_token'] = $this->refreshToken;
        }
        if ($this->idToken !== null) {
            $parameters['id_token'] = $this->idToken;
        }
        $parameters['scope'] = implode(' ', $this->scopes);

        return $parameters;
    }
}

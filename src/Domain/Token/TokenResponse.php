<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function implode;
use SensitiveParameter;

/**
 * The successful answer of the token endpoint (RFC 6749 §5.1, OIDC Core §3.1.3.3): a JSON object with
 * "access_token", "token_type" (always "Bearer", RFC 6750), "expires_in", "refresh_token" and "id_token"
 * when issued, and "scope" always, so that the client never has to guess what it got. The response
 * carries credentials: "Cache-Control: no-store" and "Pragma: no-cache" are part of it (§5.1).
 */
final readonly class TokenResponse
{
    public const string TOKEN_TYPE = 'Bearer';

    /**
     * RFC 6749 §5.1 for a success, applied to the errors of §5.2 as well: nothing the token endpoint says
     * is cached.
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
     * @param positive-int $expiresIn the lifetime of the access token in seconds
     * @param list<Scope> $scopes the scopes the access token covers, at least one
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
     * The members of the JSON object, in the order they are written.
     *
     * @return non-empty-array<string, string|positive-int>
     */
    public function parameters(): array
    {
        $parameters = [
            'access_token' => $this->accessToken,
            'token_type' => self::TOKEN_TYPE,
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

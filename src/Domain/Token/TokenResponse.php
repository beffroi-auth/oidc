<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;

/**
 * The successful answer of the token endpoint (RFC 6749 §5.1, OIDC Core §3.1.3.3); "scope" is always there.
 *
 * A grant that turns one token into another names the type of the token it issued (RFC 8693 §2.2.1), which
 * every other grant has nothing to say and therefore does not write.
 *
 * What it granted beyond its scopes is written the same way (RFC 9396 §7): a response of an authorization
 * carrying details says which, and a response of one carrying none writes no member at all. It is what a
 * client compares with what it asked for, a provider being free to grant less, and the details of a response
 * are the ones its type built rather than the objects the request wrote, so the request is not that
 * comparison (AuthorizationDetail).
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
     * @param positive-int $expiresIn
     * @param string $tokenType how the client presents the token it is handed (RFC 6749 §5.1), which is
     *                          what the binding of the token says and "Bearer" when it has none
     * @param TokenTypeIdentifier|null $issuedTokenType the type of the token this response carries (RFC 8693 §2.2.1), null for a response no exchange produced
     * @param AuthorizationDetails|null $authorizationDetails what this response granted beyond its scopes (RFC 9396 §7), null when it granted none
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

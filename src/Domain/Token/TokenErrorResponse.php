<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use Heidi\Oidc\Exception\InvalidClientException;
use Heidi\Oidc\Exception\OAuth2Exception;

/**
 * An error of the token endpoint (RFC 6749 §5.2): a JSON object with "error" and "error_description",
 * status 400, or 401 for "invalid_client" with the WWW-Authenticate challenge when the client tried the
 * Authorization header. The token endpoint never redirects: every error of the protocol ends here. The
 * introspection (RFC 7662 §2.3) and revocation (RFC 7009 §2.2.1) endpoints answer their errors the same way.
 */
final readonly class TokenErrorResponse
{
    public const string CONTENT_TYPE = 'application/json';

    /**
     * @param string|null $challenge the value of the WWW-Authenticate header, when one is due
     */
    public function __construct(
        public int $statusCode,
        public string $error,
        public string $errorDescription,
        public ?string $challenge = null,
    ) {
    }

    public static function fromException(OAuth2Exception $exception): self
    {
        return new self($exception->statusCode, $exception->error, $exception->errorDescription, $exception instanceof InvalidClientException ? $exception->challenge : null);
    }

    /**
     * The members of the JSON object, in the order they are written.
     *
     * @return non-empty-array<string, string>
     */
    public function parameters(): array
    {
        return [
            'error' => $this->error,
            'error_description' => $this->errorDescription,
        ];
    }

    /**
     * @return non-empty-array<string, string>
     */
    public function headers(): array
    {
        $headers = TokenResponse::HEADERS;
        if ($this->challenge !== null) {
            $headers['WWW-Authenticate'] = $this->challenge;
        }

        return $headers;
    }
}

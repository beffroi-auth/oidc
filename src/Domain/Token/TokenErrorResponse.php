<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use Heidi\Oidc\Exception\ChallengeInterface;
use Heidi\Oidc\Exception\InvalidClientException;
use Heidi\Oidc\Exception\OAuth2Exception;

/**
 * An error of the token endpoint (RFC 6749 §5.2), and of the introspection (RFC 7662 §2.3) and revocation
 * (RFC 7009 §2.2.1) endpoints: 400, or 401 with a challenge for "invalid_client" through the header.
 */
final readonly class TokenErrorResponse
{
    public const string CONTENT_TYPE = 'application/json';

    /**
     * @param string|null $challenge the WWW-Authenticate header, when one is due
     * @param array<string, string> $carried what the refusal carries beside its body, the nonce of
     *                                       RFC 9449 §8.1 and nothing else today
     */
    public function __construct(
        public int $statusCode,
        public string $error,
        public string $errorDescription,
        public ?string $challenge = null,
        public array $carried = [],
    ) {
    }

    public static function fromException(OAuth2Exception $exception): self
    {
        return new self(
            $exception->statusCode,
            $exception->error,
            $exception->errorDescription,
            $exception instanceof InvalidClientException ? $exception->challenge : null,
            $exception instanceof ChallengeInterface ? $exception->challengeHeaders() : [],
        );
    }

    /**
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
        $headers = TokenResponse::HEADERS + $this->carried;
        if ($this->challenge !== null) {
            $headers['WWW-Authenticate'] = $this->challenge;
        }

        return $headers;
    }
}

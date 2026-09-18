<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\UserInfo;

use Heidi\Oidc\Exception\InsufficientScopeException;
use Heidi\Oidc\Exception\MissingBearerTokenException;
use Heidi\Oidc\Exception\OAuth2Exception;
use function implode;
use function sprintf;

/**
 * An error of the UserInfo endpoint (RFC 6750 §3, OIDC Core §5.3.3): the challenge is what the protocol
 * reads, bare when the request carried no bearer token (§3.1); the body repeats it for the human.
 */
final readonly class UserInfoErrorResponse
{
    /**
     * @param string|null $scope the "scope" attribute of the challenge, for insufficient_scope
     */
    public function __construct(
        public int $statusCode,
        public ?string $error,
        public ?string $errorDescription,
        public ?string $scope = null,
    ) {
    }

    public static function fromException(OAuth2Exception|MissingBearerTokenException $exception): self
    {
        if ($exception instanceof MissingBearerTokenException) {
            return new self(MissingBearerTokenException::STATUS_CODE, null, null);
        }

        return new self($exception->statusCode, $exception->error, $exception->errorDescription, $exception instanceof InsufficientScopeException ? implode(' ', $exception->scopes) : null);
    }

    /**
     * RFC 6750 §3; the descriptions carry no double quote nor backslash and need no escaping.
     */
    public function challenge(): string
    {
        if ($this->error === null) {
            return 'Bearer';
        }
        $challenge = sprintf('Bearer error="%s"', $this->error);
        if ($this->errorDescription !== null) {
            $challenge .= sprintf(', error_description="%s"', $this->errorDescription);
        }
        if ($this->scope !== null) {
            $challenge .= sprintf(', scope="%s"', $this->scope);
        }

        return $challenge;
    }

    /**
     * @return non-empty-array<string, string>
     */
    public function headers(): array
    {
        return [
            'WWW-Authenticate' => $this->challenge(),
        ] + UserInfoResponse::HEADERS;
    }

    /**
     * @return array<string, string> empty when there is no error code
     */
    public function parameters(): array
    {
        if ($this->error === null) {
            return [];
        }
        $parameters = [
            'error' => $this->error,
        ];
        if ($this->errorDescription !== null) {
            $parameters['error_description'] = $this->errorDescription;
        }

        return $parameters;
    }
}

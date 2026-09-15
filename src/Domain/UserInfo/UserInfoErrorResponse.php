<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\UserInfo;

use Heidi\Oidc\Exception\InsufficientScopeException;
use Heidi\Oidc\Exception\MissingBearerTokenException;
use Heidi\Oidc\Exception\OAuth2Exception;
use function implode;
use function sprintf;

/**
 * An error of the UserInfo endpoint, as RFC 6750 §3 has a protected resource answer it (OIDC Core
 * §5.3.3): the status, and a "WWW-Authenticate: Bearer" challenge carrying "error", "error_description"
 * and, for insufficient_scope, the "scope" that would have sufficed. A request without any bearer token
 * gets the bare challenge, no error code (§3.1): a caller that did not know the scheme learns it, and
 * nothing else. The body repeats the error as a JSON object when there is one, for the human reading a
 * client's log; the challenge is what the protocol reads.
 */
final readonly class UserInfoErrorResponse
{
    /**
     * @param string|null $scope the "scope" attribute of the challenge, space separated, when the error is insufficient_scope
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
     * RFC 6750 §3: the value of the WWW-Authenticate header. The descriptions are the ASCII of RFC 6749
     * §5.2 without double quote nor backslash, so they need no escaping inside the quoted strings.
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
     * The members of the JSON body, in the order they are written; none when there is no error code and
     * the body is empty.
     *
     * @return array<string, string>
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

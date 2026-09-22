<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\UserInfo;

use Heidi\Oidc\Domain\Token\PresentedAccessToken;
use Heidi\Oidc\Domain\Token\TokenResponse;
use Heidi\Oidc\Exception\ChallengeInterface;
use Heidi\Oidc\Exception\InsufficientScopeException;
use Heidi\Oidc\Exception\MissingBearerTokenException;
use Heidi\Oidc\Exception\OAuth2Exception;
use function implode;
use function sprintf;

/**
 * An error of the UserInfo endpoint (RFC 6750 §3, RFC 9449 §7.1, OIDC Core §5.3.3): the challenge is
 * what the protocol reads, bare when the request carried no access token (§3.1) and naming then every
 * scheme this resource serves, so that a client learns it may bind its tokens; the body repeats it for
 * the human.
 *
 * A refusal that knows which scheme would have worked says so, and carries what the client needs to try
 * again (RFC 9449 §8.2). A challenge is a 401: the request was not honoured for want of a credential
 * this resource would take, whatever the same failure is worth at an endpoint that issues tokens.
 */
final readonly class UserInfoErrorResponse
{
    /**
     * RFC 6750 §3.1: a 401, the status of every challenge of a resource.
     */
    public const int CHALLENGED = 401;

    /**
     * @param non-empty-list<string> $schemes the schemes of the challenge, one of them save when the
     *                                        request presented no token at all
     * @param string|null $scope the "scope" attribute of the challenge, for insufficient_scope
     * @param array<string, string> $carried what the refusal carries beside the challenge
     */
    public function __construct(
        public int $statusCode,
        public ?string $error,
        public ?string $errorDescription,
        public array $schemes = [TokenResponse::BEARER],
        public ?string $scope = null,
        public array $carried = [],
    ) {
    }

    public static function fromException(OAuth2Exception|MissingBearerTokenException $exception): self
    {
        if ($exception instanceof MissingBearerTokenException) {
            return new self(MissingBearerTokenException::STATUS_CODE, null, null, PresentedAccessToken::SCHEMES);
        }
        if ($exception instanceof ChallengeInterface) {
            return new self(
                self::CHALLENGED,
                $exception->error,
                $exception->errorDescription,
                [$exception->challengeScheme()],
                null,
                $exception->challengeHeaders(),
            );
        }

        return new self(
            $exception->statusCode,
            $exception->error,
            $exception->errorDescription,
            [TokenResponse::BEARER],
            $exception instanceof InsufficientScopeException ? implode(' ', $exception->scopes) : null,
        );
    }

    /**
     * RFC 6750 §3 and RFC 9110 §11.6.1: one challenge, or the bare list of the schemes this resource
     * takes when there is nothing to say of a credential nobody sent. The descriptions carry no double
     * quote nor backslash and need no escaping.
     */
    public function challenge(): string
    {
        if ($this->error === null) {
            return implode(', ', $this->schemes);
        }
        $challenge = sprintf('%s error="%s"', $this->schemes[0], $this->error);
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
        return (
            [
                'WWW-Authenticate' => $this->challenge(),
            ]
            + $this->carried
            + UserInfoResponse::HEADERS
        );
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

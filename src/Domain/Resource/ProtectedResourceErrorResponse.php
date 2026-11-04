<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Resource;

use function array_map;
use Beffroi\Oidc\Domain\Token\TokenResponse;
use Beffroi\Oidc\Exception\ChallengeInterface;
use Beffroi\Oidc\Exception\InsufficientScopeException;
use Beffroi\Oidc\Exception\MissingBearerTokenException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Domain\UserInfo\UserInfoResponse;
use function implode;
use function sprintf;

/**
 * RFC 6750 §3, RFC 9449 §7.1, OIDC Core §5.3.3, decision 0038
 */
final readonly class ProtectedResourceErrorResponse
{
    /**
     * RFC 6750 §3.1
     */
    public const int CHALLENGED = 401;

    /**
     * @param non-empty-list<string> $schemes one, save when the request presented no token at all
     * @param array<string, string> $carried the headers beside the challenge, by name
     * @param array<string, array<string, string>> $authParameters auth-params by scheme, whatever the refusal
     */
    public function __construct(
        public int $statusCode,
        public ?string $error,
        public ?string $errorDescription,
        public array $schemes = [TokenResponse::BEARER],
        public ?string $scope = null,
        public array $carried = [],
        public array $authParameters = [],
    ) {
    }

    /**
     * @param non-empty-list<string> $schemes every scheme this resource serves
     * @param array<string, array<string, string>> $authParameters auth-params by scheme, whatever the refusal
     */
    public static function fromException(OAuth2Exception|MissingBearerTokenException $exception, array $schemes, array $authParameters): self
    {
        if ($exception instanceof MissingBearerTokenException) {
            return new self(MissingBearerTokenException::STATUS_CODE, null, null, $schemes, authParameters: $authParameters);
        }
        if ($exception instanceof InsufficientScopeException) {
            return new self(
                $exception->statusCode,
                $exception->error,
                $exception->errorDescription,
                [$exception->challengeScheme()],
                (string) $exception->scopes,
                $exception->challengeHeaders(),
                $authParameters,
            );
        }
        if ($exception instanceof ChallengeInterface) {
            return new self(
                self::CHALLENGED,
                $exception->error,
                $exception->errorDescription,
                [$exception->challengeScheme()],
                null,
                $exception->challengeHeaders(),
                $authParameters,
            );
        }

        return new self(
            $exception->statusCode,
            $exception->error,
            $exception->errorDescription,
            [TokenResponse::BEARER],
            authParameters: $authParameters,
        );
    }

    /**
     * RFC 6750 §3, RFC 9110 §11.6.1
     *
     * The descriptions and the algorithm names carry no double quote nor backslash, so nothing is escaped.
     */
    public function challenge(): string
    {
        if ($this->error === null) {
            return implode(', ', array_map($this->ofScheme(...), $this->schemes));
        }
        $parameters = [
            'error' => $this->error,
        ];
        if ($this->errorDescription !== null) {
            $parameters['error_description'] = $this->errorDescription;
        }
        if ($this->scope !== null) {
            $parameters['scope'] = $this->scope;
        }

        return $this->ofScheme($this->schemes[0], $parameters);
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

    /**
     * RFC 9110 §11.6.1
     *
     * @param array<string, string> $parameters
     */
    private function ofScheme(string $scheme, array $parameters = []): string
    {
        $parameters += $this->authParameters[$scheme] ?? [];
        if ($parameters === []) {
            return $scheme;
        }
        $written = [];
        foreach ($parameters as $name => $value) {
            $written[] = sprintf('%s="%s"', $name, $value);
        }

        return $scheme . ' ' . implode(', ', $written);
    }
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\UserInfo;

use function array_map;
use Beffroi\Oidc\Domain\Token\TokenResponse;
use Beffroi\Oidc\Exception\ChallengeInterface;
use Beffroi\Oidc\Exception\InsufficientScopeException;
use Beffroi\Oidc\Exception\MissingBearerTokenException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use function implode;
use function sprintf;

/**
 * An error of the UserInfo endpoint (RFC 6750 §3, RFC 9449 §7.1, OIDC Core §5.3.3): the challenge is
 * what the protocol reads, bare when the request carried no access token (§3.1) and naming then every
 * scheme this resource serves, so that a client learns it may bind its tokens; the body repeats it for
 * the human.
 *
 * A refusal names its scheme (`ChallengeInterface`): the one the token was presented under, whose
 * challenge delivers the error (RFC 9449 §7.2), or the one that would have worked when that is what was
 * wrong; a request refused before its token could be read is answered under the scheme of RFC 6750. Each
 * scheme also says what a client needs to present a token under it, whatever the refusal: under "DPoP",
 * the algorithms a proof may be signed with (RFC 9449 §7.1). A refusal carries what the client needs to
 * try again (RFC 9449 §8.2). A refusal of the token or of its proof is a 401: the request was not honoured
 * for want of a credential this resource would take, whatever the same failure is worth at an endpoint
 * that issues tokens; a token honoured here and not enough is a 403 (RFC 6750 §3.1).
 */
final readonly class UserInfoErrorResponse
{
    /**
     * RFC 6750 §3.1: a 401, the status of a challenge of a resource whose credential was refused.
     */
    public const int CHALLENGED = 401;

    /**
     * @param non-empty-list<string> $schemes the schemes of the challenge, one of them save when the
     *                                        request presented no token at all
     * @param string|null $scope the "scope" attribute of the challenge, for insufficient_scope
     * @param array<string, string> $carried what the refusal carries beside the challenge
     * @param array<string, array<string, string>> $authParameters what the challenge of a scheme carries
     *                                                             whatever the refusal, by scheme
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
     * @param non-empty-list<string> $schemes the schemes this resource serves, named in the bare
     *                                        challenge a request that carried no token gets (RFC 6750 §3.1)
     * @param array<string, array<string, string>> $authParameters what the challenge of a scheme carries
     *                                                             whatever the refusal, by scheme
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
     * RFC 6750 §3 and RFC 9110 §11.6.1: one challenge, or the bare list of the schemes this resource
     * takes when there is nothing to say of a credential nobody sent. The descriptions and the names of
     * the algorithms carry no double quote nor backslash and need no escaping.
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
     * A scheme and its auth-params (RFC 9110 §11.6.1): what the refusal says, then what the scheme says
     * of itself (RFC 9449 §7.1, Figure 16).
     *
     * @param array<string, string> $parameters what the refusal says
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

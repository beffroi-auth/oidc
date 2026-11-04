<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\UserInfo;

use Beffroi\Oidc\Domain\Token\JwtPayload;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * OIDC Core §5.3.2
 */
final readonly class UserInfoResponse
{
    public const string CONTENT_TYPE = 'application/json';

    /**
     * OIDC Core §5.3.2
     */
    public const string JWT_CONTENT_TYPE = 'application/jwt';

    public const array HEADERS = [
        'Cache-Control' => 'no-store',
        'Pragma' => 'no-cache',
    ];

    /**
     * @param non-empty-array<string, mixed> $claims "sub" first, then the claims
     */
    private function __construct(
        public string $subject,
        public array $claims,
        public string $contentType,
        public string $body,
    ) {
    }

    /**
     * @param array<string, mixed> $claims a "sub" among them is dropped for the token's (OIDC Core §5.3.2)
     */
    public static function json(string $subject, array $claims): self
    {
        $claims = self::claimsOf($subject, $claims);

        return new self($subject, $claims, self::CONTENT_TYPE, JwtPayload::encode($claims));
    }

    /**
     * @param array<string, mixed> $claims what the JWT carries, "iss" and "aud" included
     */
    public static function jwt(string $subject, array $claims, string $jwt): self
    {
        if ($jwt === '') {
            throw new InvalidArgumentException('A UserInfo answer served as a JWT carries one.');
        }

        return new self($subject, self::claimsOf($subject, $claims), self::JWT_CONTENT_TYPE, $jwt);
    }

    /**
     * @param array<string, mixed> $claims
     *
     * @return non-empty-array<string, mixed> "sub" first, a "sub" among the claims dropped
     */
    public static function claimsOf(string $subject, array $claims): array
    {
        if ($subject === '') {
            throw new InvalidArgumentException('A UserInfo response names its subject (OIDC Core section 5.3.2).');
        }
        unset($claims['sub']);

        return [
            'sub' => $subject,
        ] + $claims;
    }

    public function toJson(): string
    {
        return JwtPayload::encode($this->claims);
    }
}

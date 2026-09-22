<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\UserInfo;

use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Exception\InvalidArgumentException;

/**
 * The successful answer of the UserInfo endpoint (OIDC Core §5.3.2): "sub" first, every claim a JSON value
 * of its own kind, nothing cached.
 *
 * Two shapes, and the client chooses at registration: the plain JSON every client receives, and the JWT a
 * client that registered a signature or an encryption receives instead, served as "application/jwt". The
 * claims are the same in both, the JWT carrying in addition the "iss" and the "aud" that §5.3.2 requires
 * of it, and the answer says which shape it is rather than leaving the caller to guess.
 */
final readonly class UserInfoResponse
{
    public const string CONTENT_TYPE = 'application/json';

    /**
     * OIDC Core §5.3.2: what a signed or encrypted answer is served as.
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
     * @param array<string, mixed> $claims a "sub" among them is dropped, §5.3.2 makes it the token's
     */
    public static function json(string $subject, array $claims): self
    {
        $claims = self::claimsOf($subject, $claims);

        return new self($subject, $claims, self::CONTENT_TYPE, JwtPayload::encode($claims));
    }

    /**
     * @param array<string, mixed> $claims what the JWT carries, "iss" and "aud" included (§5.3.2)
     * @param string $jwt the compact JWS, or the compact JWE carrying it
     */
    public static function jwt(string $subject, array $claims, string $jwt): self
    {
        if ($jwt === '') {
            throw new InvalidArgumentException('A UserInfo answer served as a JWT carries one.');
        }

        return new self($subject, self::claimsOf($subject, $claims), self::JWT_CONTENT_TYPE, $jwt);
    }

    /**
     * The claims of an answer, whatever it is served as: the subject first, and the one of the claims
     * dropped, §5.3.2 making it the token's.
     *
     * @param array<string, mixed> $claims
     *
     * @return non-empty-array<string, mixed>
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

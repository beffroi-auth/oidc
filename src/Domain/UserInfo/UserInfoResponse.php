<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\UserInfo;

use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Exception\InvalidArgumentException;

/**
 * The successful answer of the UserInfo endpoint (OIDC Core §5.3.2): "sub" first, every claim a JSON value
 * of its own kind, nothing cached.
 */
final readonly class UserInfoResponse
{
    public const string CONTENT_TYPE = 'application/json';

    public const array HEADERS = [
        'Cache-Control' => 'no-store',
        'Pragma' => 'no-cache',
    ];

    /**
     * @var non-empty-array<string, mixed> "sub" first, then the claims
     */
    public array $claims;

    /**
     * @param array<string, mixed> $claims a "sub" among them is dropped, §5.3.2 makes it the token's
     */
    public function __construct(
        public string $subject,
        array $claims,
    ) {
        if ($subject === '') {
            throw new InvalidArgumentException('A UserInfo response names its subject (OIDC Core section 5.3.2).');
        }
        unset($claims['sub']);
        $this->claims = [
            'sub' => $subject,
        ] + $claims;
    }

    public function toJson(): string
    {
        return JwtPayload::encode($this->claims);
    }
}

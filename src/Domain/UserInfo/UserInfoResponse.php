<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\UserInfo;

use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Exception\InvalidArgumentException;

/**
 * The successful answer of the UserInfo endpoint (OIDC Core §5.3.2): a JSON object whose first member is
 * "sub", followed by the claims about the end user, each a JSON value of its own kind, never stringified.
 * The response is about a person and was obtained with a credential: nothing of it is cached (RFC 6750
 * §5.2 for the token, and the same care for what it unlocks).
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
     * @param string $subject the "sub" the token names, as the resolver of §8 rendered it
     * @param array<string, mixed> $claims the claims about the user; a "sub" among them is dropped, §5.3.2 makes it the token's
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

    /**
     * @return string the JSON object, UTF-8, booleans and numbers as they are
     */
    public function toJson(): string
    {
        return JwtPayload::encode($this->claims);
    }
}

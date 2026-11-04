<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\PushedAuthorization;

use Beffroi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;

/**
 * RFC 9126 §2.2
 */
final readonly class PushedAuthorizationResponse
{
    public const string CONTENT_TYPE = 'application/json';

    public const int STATUS_CODE = 201;

    /**
     * RFC 9126 §2.2, §2.3
     */
    public const array HEADERS = [
        'Cache-Control' => 'no-cache, no-store',
        'Pragma' => 'no-cache',
    ];

    /**
     * @param int $expiresIn seconds, at least one
     */
    public function __construct(
        #[SensitiveParameter]
        public RequestUri $requestUri,
        public int $expiresIn,
    ) {
        if ($expiresIn < 1) {
            throw new InvalidArgumentException('A request URI is answered with the seconds it still lives, at least one (RFC 9126 section 2.2).');
        }
    }

    /**
     * @return array<string, mixed>
     */
    public function parameters(): array
    {
        return [
            'request_uri' => $this->requestUri->value,
            'expires_in' => $this->expiresIn,
        ];
    }
}

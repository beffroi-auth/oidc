<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\PushedAuthorization;

use Beffroi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;

/**
 * The successful answer of the pushed authorization request endpoint (RFC 9126 §2.2): the reference and
 * how long it lives, under a 201 and never cached, the reference being a credential of one use.
 */
final readonly class PushedAuthorizationResponse
{
    public const string CONTENT_TYPE = 'application/json';

    public const int STATUS_CODE = 201;

    /**
     * RFC 9126 §2.2, for the errors of §2.3 as well.
     */
    public const array HEADERS = [
        'Cache-Control' => 'no-cache, no-store',
        'Pragma' => 'no-cache',
    ];

    /**
     * @param int $expiresIn the seconds the reference still lives, at least one (RFC 9126 §2.2)
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

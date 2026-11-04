<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Ciba;

use Beffroi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;

/**
 * CIBA Core §7.3
 */
final readonly class BackchannelAuthenticationResponse
{
    public const string CONTENT_TYPE = 'application/json';

    public const int STATUS_CODE = 200;

    /**
     * CIBA Core §7.3, §13
     */
    public const array HEADERS = [
        'Cache-Control' => 'no-store',
        'Pragma' => 'no-cache',
    ];

    /**
     * @param int $expiresIn in seconds, at least one
     * @param int $interval in seconds, at least one
     *
     * @throws InvalidArgumentException
     */
    public function __construct(
        #[SensitiveParameter]
        public string $authRequestId,
        public int $expiresIn,
        public int $interval,
    ) {
        if ($expiresIn < 1) {
            throw new InvalidArgumentException('A backchannel authentication request is answered with the seconds it still lives, at least one (CIBA Core section 7.3).');
        }
        if ($interval < 1) {
            throw new InvalidArgumentException('A backchannel authentication request is answered with a polling interval of at least one second (CIBA Core section 7.3).');
        }
    }

    /**
     * @return array<string, mixed>
     */
    public function parameters(): array
    {
        return [
            'auth_req_id' => $this->authRequestId,
            'expires_in' => $this->expiresIn,
            'interval' => $this->interval,
        ];
    }
}

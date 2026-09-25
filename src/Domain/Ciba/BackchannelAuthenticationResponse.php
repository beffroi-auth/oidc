<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Ciba;

use Heidi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;

/**
 * The successful acknowledgement of the backchannel authentication endpoint (CIBA Core §7.3): what the
 * client comes back to the token endpoint with, for how long it is worth anything, and how often it may
 * ask. Never cached, the identifier being a credential of one use.
 *
 * Three members and no more: the tokens of this flow are handed out at the token endpoint and nowhere
 * else, which is what makes "push" a mode this provider does not serve (§10.3, decision 0006).
 */
final readonly class BackchannelAuthenticationResponse
{
    public const string CONTENT_TYPE = 'application/json';

    public const int STATUS_CODE = 200;

    /**
     * CIBA Core §7.3, for the errors of §13 as well.
     */
    public const array HEADERS = [
        'Cache-Control' => 'no-store',
        'Pragma' => 'no-cache',
    ];

    /**
     * @param string $authRequestId what the client comes back to the token endpoint with (§7.3)
     * @param int $expiresIn the seconds the request still lives, at least one
     * @param int $interval the seconds the client waits between two polls, at least one
     *
     * @throws InvalidArgumentException when the answer says nothing a client could use
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

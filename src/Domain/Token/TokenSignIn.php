<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Symfony\Component\Uid\Uuid;

final readonly class TokenSignIn
{
    public function __construct(
        public Uuid $sessionId,
        public AuthenticationSnapshot $authentication,
    ) {
    }

    /**
     * @return array{auth_time: int, acr: string, amr: non-empty-list<string>, sid: string}
     */
    public function toClaims(): array
    {
        return [
            ...$this->authentication->toClaims(),
            'sid' => $this->sessionId->toRfc4122(),
        ];
    }
}

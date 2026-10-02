<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Symfony\Component\Uid\Uuid;

/**
 * The sign-in an access token descends from (OIDC Core §2, architecture §4.6): the session it names in
 * "sid" (OIDC Front-Channel Logout §3), and what that session had proven when the authorization was
 * granted. Both shapes of access token write it, the introspection response renders it and the verifiers
 * read it back, so what a token says of a sign-in is one value and not four claims travelling together.
 *
 * A token a client holds for itself carries none of it (RFC 6749 §4.4), and what the provider asks of a
 * session and of a user it asks of the tokens that carry this and of no other.
 */
final readonly class TokenSignIn
{
    public function __construct(
        public Uuid $sessionId,
        public AuthenticationSnapshot $authentication,
    ) {
    }

    /**
     * The claims of the sign-in, in the order every token and every introspection response of the
     * provider writes them.
     *
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

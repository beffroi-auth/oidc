<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\EndSession;

use DateTimeImmutable;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Tenant\Issuer;
use stdClass;
use Symfony\Component\Uid\Uuid;

/**
 * The claims of a logout token (Back-Channel Logout 1.0 §2.4): the security event token (RFC 8417 §2)
 * that says one session of one subject ended at the provider, and says nothing else. Both "sub" and
 * "sid" are sent, so that a client identifies the session whether it kept one or not (§2.4 requires one
 * of the two). No "nonce" (§2.4: a logout token that carries one is refused, which is how a client tells
 * it from an ID token) and no "exp" (RFC 8417 §2: a SET states what happened, it does not expire; what
 * bounds a delivery is the retries of the sender, not a claim).
 */
final readonly class LogoutToken
{
    /**
     * Back-Channel Logout 1.0 §2.4: the one member of "events", whose value is an empty JSON object.
     */
    public const string EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    /**
     * RFC 8417 §2.3, Back-Channel Logout 1.0 §2.4: the "typ" header of a logout token.
     */
    public const string TYPE = 'logout+jwt';

    public function __construct(
        public Issuer $issuer,
        public string $audience,
        public Subject $subject,
        public Uuid $sessionId,
        public Uuid $jti,
        public DateTimeImmutable $issuedAt,
    ) {
    }

    /**
     * In the order Back-Channel Logout 1.0 §2.4 lists them.
     *
     * @return array<string, mixed>
     */
    public function claims(): array
    {
        return [
            'iss' => (string) $this->issuer,
            'sub' => $this->subject->value,
            'aud' => $this->audience,
            'iat' => $this->issuedAt->getTimestamp(),
            'jti' => $this->jti->toRfc4122(),
            // an empty JSON object, which an empty PHP array would write as "[]"
            'events' => [
                self::EVENT => new stdClass(),
            ],
            'sid' => $this->sessionId->toRfc4122(),
        ];
    }
}

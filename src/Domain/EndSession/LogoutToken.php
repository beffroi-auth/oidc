<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\EndSession;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Issuer;
use stdClass;
use Symfony\Component\Uid\Uuid;

/**
 * The claims of a logout token (Back-Channel Logout 1.0 §2.4): the security event token (RFC 8417 §2)
 * that says one session of one subject ended at the provider, and says nothing else. Both "sub" and
 * "sid" are sent, so that a client identifies the session whether it kept one or not (§2.4 requires one
 * of the two). No "nonce" (§2.4: a logout token that carries one is refused, which is how a client tells
 * it from an ID token).
 *
 * **It expires**, §2.4 listing "exp" among the claims it requires and §2.6 asking a client to check it
 * the way it checks the one of an ID token. RFC 8417 §2.2 does not recommend one on a security event
 * token, which is the base specification; this profile requires it, and the profile is what a relying
 * party implements. Which instant it is belongs to whoever mints the token (`LogoutTokenIssuer`): the end
 * of the delivery this provider is willing to attempt, so the token stops being valid at the moment
 * nobody is trying to deliver it any more.
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
        public DateTimeImmutable $expiresAt,
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
            'exp' => $this->expiresAt->getTimestamp(),
            'jti' => $this->jti->toRfc4122(),
            // an empty JSON object, which an empty PHP array would write as "[]"
            'events' => [
                self::EVENT => new stdClass(),
            ],
            'sid' => $this->sessionId->toRfc4122(),
        ];
    }
}

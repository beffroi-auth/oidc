<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\EndSession;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Issuer;
use stdClass;
use Symfony\Component\Uid\Uuid;

/**
 * Back-Channel Logout 1.0 §2.4
 */
final readonly class LogoutToken
{
    public const string EVENT = 'http://schemas.openid.net/event/backchannel-logout';

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
            // An empty JSON object, which an empty PHP array would encode as "[]".
            'events' => [
                self::EVENT => new stdClass(),
            ],
            'sid' => $this->sessionId->toRfc4122(),
        ];
    }
}

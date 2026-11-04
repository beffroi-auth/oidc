<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use DateTimeImmutable;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;

/**
 * RFC 6749 §5.1
 */
final readonly class AccessToken
{
    public function __construct(
        #[SensitiveParameter]
        public string $value,
        public DateTimeImmutable $issuedAt,
        public DateTimeImmutable $expiresAt,
    ) {
        if ($value === '') {
            throw new InvalidArgumentException('An access token has a value.');
        }
        if ($expiresAt->getTimestamp() <= $issuedAt->getTimestamp()) {
            throw new InvalidArgumentException('An access token expires at least one second after it was issued.');
        }
    }

    /**
     * @return positive-int
     */
    public function expiresIn(): int
    {
        /** @var positive-int $seconds */
        $seconds = $this->expiresAt->getTimestamp() - $this->issuedAt->getTimestamp();

        return $seconds;
    }
}

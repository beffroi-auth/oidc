<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use DateTimeImmutable;
use Heidi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;

/**
 * An access token as the token endpoint hands it out (RFC 6749 §1.4, §5.1): the value the client will
 * present, and until when it is valid. Stateless: nothing of it is stored (architecture §4.6); what the
 * value contains is the issuer's business.
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
     * RFC 6749 §5.1 "expires_in": the lifetime in seconds, counted from issuance.
     *
     * @return positive-int
     */
    public function expiresIn(): int
    {
        /** @var positive-int $seconds the constructor guarantees it */
        $seconds = $this->expiresAt->getTimestamp() - $this->issuedAt->getTimestamp();

        return $seconds;
    }
}

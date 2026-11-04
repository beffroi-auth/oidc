<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Exchange;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Exception\InvalidArgumentException as CoreInvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function is_array;
use function is_string;

/**
 * RFC 8693 §4.1
 */
final readonly class Actor
{
    public function __construct(
        public Subject $subject,
        public ?self $actor = null,
    ) {
    }

    public function actingThrough(?self $previous): self
    {
        return new self($this->subject, $previous);
    }

    /**
     * @return array{sub: string, act?: array<string, mixed>}
     */
    public function toClaim(): array
    {
        $claim = [
            'sub' => $this->subject->value,
        ];
        if ($this->actor !== null) {
            $claim['act'] = $this->actor->toClaim();
        }

        return $claim;
    }

    /**
     * @throws InvalidArgumentException
     */
    public static function fromClaim(mixed $act): self
    {
        if (! is_array($act)) {
            throw new InvalidArgumentException('An "act" claim is a JSON object (RFC 8693 section 4.1).');
        }
        $subject = $act['sub'] ?? null;
        if (! is_string($subject)) {
            throw new InvalidArgumentException('An "act" claim names the actor in its "sub" (RFC 8693 section 4.1).');
        }
        try {
            return new self(new Subject($subject), isset($act['act']) ? self::fromClaim($act['act']) : null);
        } catch (CoreInvalidArgumentException $exception) {
            throw new InvalidArgumentException('The "sub" of an "act" claim is a subject (OIDC Core section 2).', previous: $exception);
        }
    }

    public function equals(self $other): bool
    {
        return (
            $this->subject->equals($other->subject)
            && ($this->actor === null ? $other->actor === null : $other->actor !== null && $this->actor->equals($other->actor))
        );
    }
}

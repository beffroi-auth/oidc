<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Exchange;

use Beffroi\Core\Domain\Identity\Subject;

/**
 * RFC 8693 §4.4
 */
final readonly class MayAct
{
    public function __construct(
        public Subject $subject,
    ) {
    }

    public function allows(Actor $actor): bool
    {
        return $this->subject->equals($actor->subject);
    }

    /**
     * @return array{sub: string}
     */
    public function toClaim(): array
    {
        return [
            'sub' => $this->subject->value,
        ];
    }

    public function equals(self $other): bool
    {
        return $this->subject->equals($other->subject);
    }
}

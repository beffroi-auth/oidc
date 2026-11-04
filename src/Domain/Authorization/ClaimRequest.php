<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

/**
 * OIDC Core §5.5.1
 */
final readonly class ClaimRequest
{
    /**
     * @param list<string|int|float|bool>|null $values
     */
    public function __construct(
        public bool $essential = false,
        public string|int|float|bool|null $value = null,
        public ?array $values = null,
    ) {
    }
}

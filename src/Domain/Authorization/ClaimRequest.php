<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

/**
 * What a client asks about one claim (OIDC Core §5.5.1); a value is kept as the client sent it.
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

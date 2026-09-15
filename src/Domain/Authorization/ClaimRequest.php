<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

/**
 * What a client asks about one claim (OIDC Core §5.5.1): whether it is essential, and which value or
 * set of values it expects. A value is a JSON scalar, kept as the client sent it; a boolean here is a
 * JSON boolean, never a string that looked like one.
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

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

/**
 * RFC 6750 §2.1, RFC 9449 §7.1
 */
interface ServedTokenSchemesInterface
{
    /**
     * @return non-empty-list<non-empty-string> each once, the scheme of a token bound to nothing first
     */
    public function servedTokenSchemes(): array;
}

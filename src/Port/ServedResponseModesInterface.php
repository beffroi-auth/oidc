<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

interface ServedResponseModesInterface
{
    /**
     * @return non-empty-list<string> the first is the fallback of a request that cannot be answered as it asked
     */
    public function servedResponseModes(): array;

    /**
     * Resolves the alias of JARM §2.1 against what the wiring serves.
     */
    public function responseModeNamed(string $requested): ?string;

    public function signsAnyAnswer(): bool;
}

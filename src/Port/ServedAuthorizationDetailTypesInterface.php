<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Exception\InvalidArgumentException;

interface ServedAuthorizationDetailTypesInterface
{
    /**
     * @throws InvalidArgumentException when two wired types answer for one "type"
     *
     * @return list<non-empty-string> each once
     */
    public function servedAuthorizationDetailTypes(): array;
}

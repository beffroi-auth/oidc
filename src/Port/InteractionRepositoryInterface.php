<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Interaction\Interaction;

interface InteractionRepositoryInterface
{
    public function find(string $id): ?Interaction;

    public function save(Interaction $interaction): void;
}

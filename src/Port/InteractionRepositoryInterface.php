<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Interaction\Interaction;

interface InteractionRepositoryInterface
{
    /**
     * @param string $id as the integration holds it in the browser session; the match is exact
     */
    public function find(string $id): ?Interaction;

    public function save(Interaction $interaction): void;
}

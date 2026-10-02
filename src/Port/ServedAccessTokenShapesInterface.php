<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\AccessTokenShapeInterface;

/**
 * The shapes the provider is wired to write its access tokens in (architecture §4.6), the one source of
 * truth over them: what a client may register reads this list, what reads a token back is checked
 * against it, and the first of them is the shape a client that registers none takes. The configuration
 * tree cannot know that list, so a registration naming a shape nobody writes is refused with it.
 */
interface ServedAccessTokenShapesInterface
{
    /**
     * @return non-empty-list<AccessTokenShapeInterface> in the order they are wired
     */
    public function servedAccessTokenShapes(): array;
}

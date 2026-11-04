<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Interaction;

/**
 * What the authorization handler tells the integration to do next.
 */
interface AuthorizationDecision
{
    public Interaction $interaction { get; }

    /**
     * @return non-empty-string
     */
    public function name(): string;
}

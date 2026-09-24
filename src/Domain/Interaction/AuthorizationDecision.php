<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Interaction;

/**
 * What the authorization handler tells the integration to do next (architecture §4.3). An error is an
 * OAuth2Exception carrying the redirectable flag.
 */
interface AuthorizationDecision
{
    public Interaction $interaction { get; }

    /**
     * What was decided, under the name the integration answers it by: a decision the provider gains is
     * a class here and a way of answering it in the integration, and nothing reads a class name to tell
     * one decision from another.
     *
     * @return non-empty-string
     */
    public function name(): string;
}

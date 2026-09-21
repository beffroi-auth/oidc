<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Tenant\Tenant;

/**
 * Whether every client of a tenant may only start an authorization request by pushing it (RFC 9126 §5).
 * The document says what is wired and nothing else (issue #98): a provider requires it of a tenant when
 * every client registered there requires it, and a single client that does not is what makes the answer
 * false, so the document and the endpoint cannot disagree.
 */
interface PushedAuthorizationRequirementInterface
{
    public function requiresPushedAuthorizationRequests(Tenant $tenant): bool;
}

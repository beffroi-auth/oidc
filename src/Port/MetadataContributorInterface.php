<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * OIDC Discovery §3, RFC 8414 §2
 */
interface MetadataContributorInterface
{
    /**
     * @throws InvalidArgumentException when what the deployment wired cannot be announced
     *
     * @return array<string, mixed> empty when the deployment does not serve this capability
     */
    public function metadata(Tenant $tenant): array;
}

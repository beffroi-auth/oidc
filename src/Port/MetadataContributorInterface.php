<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Exception\InvalidArgumentException;

/**
 * What one specification the provider implements adds to the document it publishes (OIDC Discovery §3,
 * RFC 8414 §2). A provider announces what it is wired with, so each capability says for itself what it
 * puts in the document, and nothing assembles a list of them: the document is what the wired
 * contributors contribute, in the order they are wired.
 *
 * This is what a capability costs: a class beside the others and a line in the wiring. Nothing that
 * assembles the document is touched, because nothing assembles it.
 *
 * A contributor announces nothing at all rather than an empty member: a deployment that does not serve
 * something says nothing of it, which is what a client reads as "not served".
 */
interface MetadataContributorInterface
{
    /**
     * The members this capability puts in the document of that tenant, in the order they are published.
     *
     * @throws InvalidArgumentException when what the deployment wired cannot be announced: a capability
     *                                  refuses rather than announce something a client would misread,
     *                                  and a deployment learns it at boot
     *
     * @return array<string, mixed> empty when the deployment does not serve this capability
     */
    public function metadata(Tenant $tenant): array;
}

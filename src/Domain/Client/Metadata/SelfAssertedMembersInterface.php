<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

/**
 * RFC 7591 §5
 *
 * What a client says of itself and nobody vouches for: neither a deployment that declares it nor an authority that
 * signs a statement about it.
 */
interface SelfAssertedMembersInterface extends ClientMetadataSourceInterface
{
}

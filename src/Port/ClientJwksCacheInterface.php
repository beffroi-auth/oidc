<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\CachedClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;

/**
 * Where the keys read back from a "jwks_uri" are kept between requests, with the moment they were read.
 * Shared by the workers of a deployment, so that a rotation costs one read and not one per worker.
 *
 * A set is filed under the URL it was read from, because that URL is what identifies the document and
 * whoever registered it does not: two parties publishing behind the same URL publish the same keys, and
 * a party that moves its keys elsewhere must not be verified against what the URL it left answered.
 */
interface ClientJwksCacheInterface
{
    public function read(ClientUri $jwksUri): ?CachedClientJwks;

    public function write(ClientUri $jwksUri, CachedClientJwks $keys): void;
}

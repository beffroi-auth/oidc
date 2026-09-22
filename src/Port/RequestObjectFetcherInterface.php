<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Client\ClientUri;
use Heidi\Oidc\Exception\RequestObjectUnavailableException;

/**
 * Reads back the request object a client publishes behind a "request_uri" (RFC 9101 §5.2, OIDC Core §6.2).
 * One GET over HTTPS, no redirect followed (decision 0006), a bounded body and a timeout of its own: a
 * client that hangs or answers a gigabyte must not hold a worker, and a client that redirects names
 * another URL than the one it registered. Only a URL the client registered is ever read, which the
 * caller has checked before anything leaves the process.
 */
interface RequestObjectFetcherInterface
{
    /**
     * @throws RequestObjectUnavailableException
     */
    public function fetch(ClientUri $requestUri): string;
}

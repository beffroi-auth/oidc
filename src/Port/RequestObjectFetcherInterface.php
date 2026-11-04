<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\RequestObjectUnavailableException;

/**
 * RFC 9101 §5.2, OIDC Core §6.2
 *
 * One GET over HTTPS, no redirect followed (decision 0006), a bounded body and a timeout of its own.
 */
interface RequestObjectFetcherInterface
{
    /**
     * @throws RequestObjectUnavailableException
     */
    public function fetch(ClientUri $requestUri): string;
}

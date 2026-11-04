<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Flow;

/**
 * One of the parties a flow is drawn between.
 */
enum Actor: string
{
    case Browser = 'browser';

    case Client = 'client';

    case Provider = 'provider';

    case ResourceServer = 'resource_server';
}

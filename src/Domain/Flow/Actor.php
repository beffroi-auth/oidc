<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Flow;

/**
 * One of the four parties a flow of this provider is played between (issue #462): the browser of
 * whoever is signing in, the client asking for the tokens, this provider, and the resource server the
 * tokens are spent at. Every hop of every picture goes from one of them to another, which is what lets
 * one drawing serve every flow.
 *
 * A closed set the drawing fixes, carried by a hop and acted on by nobody: a picture reads the actors of
 * its hops to know which columns it has, and nothing branches on which one a hop names.
 */
enum Actor: string
{
    case Browser = 'browser';

    case Client = 'client';

    case Provider = 'provider';

    case ResourceServer = 'resource_server';
}

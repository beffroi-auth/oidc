<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Flow;

use function array_merge;
use Beffroi\Oidc\Domain\Client\GrantTypesApart;
use Beffroi\Oidc\Domain\Flow\TokenEndpointHops;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * The flow of a grant that asks nobody anything (RFC 6749 §4.5): it carries its own authorization,
 * a refresh token, an assertion, a token to exchange, so its picture opens at the token endpoint and
 * ends one answer later.
 *
 * Which grants those are is read as what is left: the wired grants none of the ways of asking a user
 * claims. A capability added to the provider brings its own shape, and the grants that declare it leave
 * this one without a line being edited here.
 */
final readonly class TheClientAsksForATokenAlone implements FlowShapeInterface
{
    public function grantTypes(ServedGrantsInterface $served): array
    {
        return GrantTypesApart::of($served->servedGrantTypes(), array_merge(
            $served->sendingTheUserToTheClient(),
            $served->askingTheUserOnAnotherDevice(),
            $served->askingTheUserThroughABackchannel(),
            $served->actingForTheClientItself(),
        ));
    }

    public function hops(): array
    {
        return TokenEndpointHops::askedAndAnswered('RFC 6749 §3.2', 'RFC 6749 §5.1');
    }
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Flow;

use Beffroi\Oidc\Domain\Flow\Actor;
use Beffroi\Oidc\Domain\Flow\Hop;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * How a flow of this provider ends (RFC 7009 §2): the client gives the token back, and is answered the
 * same way whether the token was live, already dead or never existed. Every flow ends in a token, so
 * every one of them can end here.
 */
final readonly class TheTokenIsGivenBack implements FlowShapeInterface
{
    public const string REVOCATION_REQUEST = 'revocation_request';

    public const string REVOCATION_RESPONSE = 'revocation_response';

    public function grantTypes(ServedGrantsInterface $served): array
    {
        return $served->servedGrantTypes();
    }

    public function hops(): array
    {
        return [
            new Hop(Actor::Client, Actor::Provider, self::REVOCATION_REQUEST, 'RFC 7009 §2.1'),
            new Hop(Actor::Provider, Actor::Client, self::REVOCATION_RESPONSE, 'RFC 7009 §2.2'),
        ];
    }
}

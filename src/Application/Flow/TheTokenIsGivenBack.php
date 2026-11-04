<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Flow;

use Beffroi\Oidc\Domain\Flow\Actor;
use Beffroi\Oidc\Domain\Flow\Hop;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * RFC 7009 §2
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

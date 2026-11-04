<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Flow;

use Beffroi\Oidc\Domain\Client\GrantTypesApart;
use Beffroi\Oidc\Domain\Flow\Actor;
use Beffroi\Oidc\Domain\Flow\Hop;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * OIDC Core §5.3
 */
final readonly class TheProviderIsAskedWhoTheUserIs implements FlowShapeInterface
{
    public const string USERINFO_REQUEST = 'userinfo_request';

    public const string USERINFO_RESPONSE = 'userinfo_response';

    public function grantTypes(ServedGrantsInterface $served): array
    {
        return GrantTypesApart::of($served->servedGrantTypes(), $served->actingForTheClientItself());
    }

    public function hops(): array
    {
        return [
            new Hop(Actor::Client, Actor::Provider, self::USERINFO_REQUEST, 'OIDC Core §5.3.1'),
            new Hop(Actor::Provider, Actor::Client, self::USERINFO_RESPONSE, 'OIDC Core §5.3.2'),
        ];
    }
}

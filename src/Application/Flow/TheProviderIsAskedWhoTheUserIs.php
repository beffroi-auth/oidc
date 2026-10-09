<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Flow;

use Beffroi\Oidc\Domain\Client\GrantTypesApart;
use Beffroi\Oidc\Domain\Flow\Actor;
use Beffroi\Oidc\Domain\Flow\Hop;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * What a client does with a token once it holds one, when there is somebody behind it (OIDC Core §5.3):
 * it asks this provider who that is. A flow a client uses for itself has nobody to ask about, so it is
 * the one that does not close this way.
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

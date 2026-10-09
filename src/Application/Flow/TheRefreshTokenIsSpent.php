<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Flow;

use Beffroi\Oidc\Domain\Flow\Actor;
use Beffroi\Oidc\Domain\Flow\Hop;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * What a client does when the access token it was given runs out and it was given a refresh token with
 * it (RFC 6749 §6): it spends that one and is given another pair, without the user being asked
 * anything again. The flows that close this way are the ones whose answer may carry a refresh token,
 * which is what their grants declare.
 */
final readonly class TheRefreshTokenIsSpent implements FlowShapeInterface
{
    public const string REFRESH_REQUEST = 'refresh_request';

    public const string REFRESH_RESPONSE = 'refresh_response';

    public function grantTypes(ServedGrantsInterface $served): array
    {
        return $served->issuingRefreshTokens();
    }

    public function hops(): array
    {
        return [
            new Hop(Actor::Client, Actor::Provider, self::REFRESH_REQUEST, 'RFC 6749 §6'),
            new Hop(Actor::Provider, Actor::Client, self::REFRESH_RESPONSE, 'RFC 6749 §5.1'),
        ];
    }
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Flow;

final readonly class TokenEndpointHops
{
    public const string REQUEST = 'token_request';

    public const string RESPONSE = 'token_response';

    /**
     * @param non-empty-string $request the specification section the token request follows
     * @param non-empty-string $response the specification section the answer follows
     *
     * @return non-empty-list<Hop>
     */
    public static function askedAndAnswered(string $request, string $response, bool $repeats = false): array
    {
        return [
            new Hop(Actor::Client, Actor::Provider, self::REQUEST, $request, $repeats),
            new Hop(Actor::Provider, Actor::Client, self::RESPONSE, $response),
        ];
    }
}

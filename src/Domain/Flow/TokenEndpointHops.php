<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Flow;

/**
 * The two hops every flow of this provider ends its way to a token with, whatever brought it there
 * (RFC 6749 §3.2): the client asks the token endpoint and the endpoint answers. Every shape that draws
 * a flow draws them, each with the section of the specification that says what its own request carries,
 * so the pair is written once and the reading of it stays each shape's own.
 */
final readonly class TokenEndpointHops
{
    public const string REQUEST = 'token_request';

    public const string RESPONSE = 'token_response';

    /**
     * @param non-empty-string $request  the section that says what this flow's token request carries
     * @param non-empty-string $response the section that says what it is answered
     * @param bool             $repeats  true for a flow whose client asks again until the user has
     *                                   answered somewhere else (RFC 8628 §3.4, CIBA Core §10.1)
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

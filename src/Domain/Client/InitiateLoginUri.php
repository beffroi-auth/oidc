<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Oidc\Exception\InvalidArgumentException;
use function is_string;
use function parse_url;
use const PHP_URL_SCHEME;
use function sprintf;
use Stringable;
use function strtolower;

/**
 * Where a third party sends a user to have this provider begin a login at a client (OIDC Core §4): the
 * "initiate_login_uri" that client registered. What may be registered at all is ClientUri; this is what
 * OIDC Registration §2 asks of this one member, which is an "https" URL and nothing else.
 *
 * ClientUri accepts plain HTTP on a loopback host, which is what the URIs of a client on a development
 * stack are, and §2 gives this member none of that tolerance: the exception stays where it is earned and is
 * named per kind rather than lifted for every member at once (decision 0006). The rule is on the member and
 * not on the environment, so a tenant of a deployment is refused the same way.
 *
 * It is a kind of its own for the same reason RedirectUri is one: what a URI is good for is the class that
 * holds it, and what that use asks of it is that class's rule.
 */
final readonly class InitiateLoginUri implements Stringable
{
    public string $value;

    private ClientUri $uri;

    /**
     * The scheme is read before the URI is parsed, so that the member this rule belongs to is the one the
     * refusal names, whatever the host: a client reads that name in the "error_description" of RFC 7591
     * §3.2.2 and a deployment reads it in a boot that stopped. Everything else a URI a client registers
     * must be is ClientUri's, and a value that carries no scheme at all is answered for there.
     *
     * @throws InvalidArgumentException when it is not a URI a client may register, or not an HTTPS one
     */
    public function __construct(string $value)
    {
        $scheme = parse_url($value, PHP_URL_SCHEME);
        if (is_string($scheme) && strtolower($scheme) !== 'https') {
            throw new InvalidArgumentException(sprintf(
                'The initiate_login_uri "%s" must use HTTPS, on a loopback host as anywhere else (OIDC Registration §2).',
                $value,
            ));
        }

        $this->uri = new ClientUri($value);
        $this->value = $this->uri->value;
    }

    /**
     * The query the client registered is kept and the parameters of OIDC Core §4 are added to it
     * (ClientUri::withParameters).
     *
     * @param non-empty-array<string, string> $parameters
     */
    public function withParameters(array $parameters): string
    {
        return $this->uri->withParameters($parameters);
    }

    public function __toString(): string
    {
        return $this->value;
    }
}

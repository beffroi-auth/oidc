<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client;

use function array_values;
use Heidi\Oidc\Application\Client\Method\AuthenticationMethodInterface;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Port\ClientAuthenticationMethodsInterface;
use function sprintf;

/**
 * The client authentication methods the wiring gave the provider, in the order they are wired. The one
 * source of truth over them (issue #98): the authenticator reads this list to know what a request may
 * present, a registration reads it to know what a client may name, and the discovery document reads it
 * to know what to announce. The first wired one is what a client that names none registers.
 */
final readonly class ClientAuthenticationMethods implements ClientAuthenticationMethodsInterface
{
    /**
     * @var non-empty-list<AuthenticationMethodInterface>
     */
    private array $methods;

    /**
     * @param iterable<AuthenticationMethodInterface> $methods at least one
     */
    public function __construct(iterable $methods)
    {
        $wired = [];
        foreach ($methods as $method) {
            $name = $method->name();
            if (isset($wired[$name])) {
                throw new InvalidArgumentException(sprintf('The client authentication method "%s" is wired twice.', $name));
            }
            $wired[$name] = $method;
        }
        if ($wired === []) {
            throw new InvalidArgumentException('A provider authenticates its clients with at least one method.');
        }
        $this->methods = array_values($wired);
    }

    /**
     * @return non-empty-list<AuthenticationMethodInterface>
     */
    public function clientAuthenticationMethods(): array
    {
        return $this->methods;
    }
}

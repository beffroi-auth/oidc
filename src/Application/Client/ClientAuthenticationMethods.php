<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use function array_values;
use Beffroi\Oidc\Application\Client\Method\AuthenticationMethodInterface;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\ClientAuthenticationMethodsInterface;
use function sprintf;

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

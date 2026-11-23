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
 * OIDC Core §4, OIDC Registration §2
 *
 * HTTPS even on a loopback host, where ClientUri accepts plain HTTP.
 */
final readonly class InitiateLoginUri implements Stringable
{
    public string $value;

    public string $host;

    private ClientUri $uri;

    /**
     * @throws InvalidArgumentException
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
        $this->host = $this->uri->host;
    }

    /**
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

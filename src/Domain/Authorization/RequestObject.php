<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

use Beffroi\Oidc\Domain\Client\RequestObject\UnsignedRequestObjects;
use Beffroi\Oidc\Domain\Token\JwtPayload;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidRequestObjectException;
use function array_all;
use function array_is_list;
use function in_array;
use function is_array;
use function is_int;
use function is_string;
use function sprintf;

/**
 * RFC 9101 §4, OIDC Core §6
 *
 * Read, not verified. A refusal never names the claim, a string the client chose: RFC 6749 §5.2 restricts the
 * characters of an error description.
 */
final readonly class RequestObject
{
    /**
     * RFC 7519 §4.1
     */
    private const array REGISTERED_CLAIMS = ['iss', 'aud', 'exp', 'nbf', 'iat', 'jti'];

    /**
     * RFC 9101 §4
     */
    private const array NESTED_PARAMETERS = ['request', 'request_uri'];

    public function __construct(
        public UnverifiedJwt $jwt,
    ) {
    }

    /**
     * RFC 7515 §4.1.1, RFC 7518 §3.6
     */
    public function isSigned(): bool
    {
        return $this->jwt->algorithm() !== UnsignedRequestObjects::ALGORITHM;
    }

    /**
     * @throws InvalidRequestObjectException
     *
     * @return array<string, string|list<string>>
     */
    public function parameters(): array
    {
        $parameters = [];
        foreach ($this->jwt->claims as $name => $value) {
            if (! is_string($name)) {
                continue;
            }
            if (in_array($name, self::REGISTERED_CLAIMS, true)) {
                continue;
            }
            if (in_array($name, self::NESTED_PARAMETERS, true)) {
                throw new InvalidRequestObjectException(sprintf('A request object carries no %s parameter of its own (RFC 9101 section 4).', $name));
            }
            $parameters[$name] = $this->parameter($value);
        }

        return $parameters;
    }

    /**
     * @throws InvalidRequestObjectException
     *
     * @return string|list<string>
     */
    private function parameter(mixed $value): string|array
    {
        if (is_string($value)) {
            return $value;
        }
        if (is_int($value)) {
            return (string) $value;
        }
        if (is_array($value) && array_is_list($value) && array_all($value, static fn (mixed $item): bool => is_string($item))) {
            /** @var list<string> $value */
            return $value;
        }
        if (is_array($value)) {
            /** @var array<string, mixed> $value */
            return JwtPayload::encode($value);
        }

        throw new InvalidRequestObjectException('A claim of the request object holds a value no authorization request carries (OIDC Core section 6.1).');
    }
}

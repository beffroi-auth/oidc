<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use Heidi\Oidc\Domain\Client\RequestObject\UnsignedRequestObjects;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Domain\Token\UnverifiedJwt;
use Heidi\Oidc\Exception\InvalidRequestObjectException;
use function in_array;
use function is_array;
use function is_int;
use function is_string;
use function sprintf;

/**
 * An authorization request a client carried in a JWT (RFC 9101 §4, OIDC Core §6), read but not yet
 * verified. The claims of the JWT are the parameters of the request, save the ones RFC 7519 §4.1 reserves
 * for what a token says about itself; those are the validator's and never a parameter.
 *
 * OIDC Core §6.1 lets a parameter be any JSON value, "max_age" as a number and "claims" as an object
 * being the two the field sends; each is written back as the query would have carried it. A boolean, a
 * fraction or a null is no parameter of an authorization request and is refused rather than cast
 * (decision 0006).
 */
final readonly class RequestObject
{
    /**
     * RFC 7519 §4.1: what the JWT says about itself.
     */
    private const array REGISTERED_CLAIMS = ['iss', 'aud', 'exp', 'nbf', 'iat', 'jti'];

    /**
     * RFC 9101 §4: an object carries the request, never another object.
     */
    private const array NESTED_PARAMETERS = ['request', 'request_uri'];

    public function __construct(
        public UnverifiedJwt $jwt,
    ) {
    }

    /**
     * Whether the object carries a signature at all (RFC 7515 §4.1.1, RFC 7518 §3.6). An object with
     * "alg": "none" is read from the one client that registered it (decision 0006) and proves nothing:
     * whoever wrote it wrote its claims too.
     */
    public function isSigned(): bool
    {
        return $this->jwt->algorithm() !== UnsignedRequestObjects::ALGORITHM;
    }

    /**
     * The parameters of the authorization request, as the endpoint that reads a query reads them.
     *
     * @throws InvalidRequestObjectException
     *
     * @return array<string, string>
     */
    public function parameters(): array
    {
        $parameters = [];
        foreach ($this->jwt->claims as $name => $value) {
            if (in_array($name, self::REGISTERED_CLAIMS, true)) {
                continue;
            }
            if (in_array($name, self::NESTED_PARAMETERS, true)) {
                throw new InvalidRequestObjectException(sprintf('A request object carries no %s parameter of its own (RFC 9101 section 4).', $name));
            }
            $parameters[$name] = $this->parameter($name, $value);
        }

        return $parameters;
    }

    /**
     * @throws InvalidRequestObjectException
     */
    private function parameter(string $name, mixed $value): string
    {
        if (is_string($value)) {
            return $value;
        }
        if (is_int($value)) {
            return (string) $value;
        }
        if (is_array($value)) {
            /** @var array<string, mixed> $value */
            return JwtPayload::encode($value);
        }

        throw new InvalidRequestObjectException(sprintf('The %s claim of a request object is not a value an authorization request carries (OIDC Core section 6.1).', $name));
    }
}

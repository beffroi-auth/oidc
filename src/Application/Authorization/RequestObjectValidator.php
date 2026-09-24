<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Authorization;

use DateInterval;
use DateTimeImmutable;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Authorization\RequestObject;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Exception\InvalidRequestObjectException;
use function in_array;

/**
 * What a request object has to say once its signature has been verified (RFC 9101 §6.1, OIDC Core §6.1).
 * "iss" names the client, so an object minted for one client cannot be presented for another. "aud"
 * names the issuer of the tenant, so an object minted for another provider, or for another tenant of
 * this one, is not replayed here (RFC 9101 §10.2). "exp" and "nbf" are both there and bounded, so that
 * an object is a request made now and not a bearer authorization a client keeps for a year, which is
 * what FAPI 2.0 Message Signing asks of one. The "client_id" the object carries is the one the request
 * names outside it, the two being one client.
 *
 * Those four claims bound what a signature proves, and they are asked of an object that carries one.
 * An object with "alg": "none", read from the one client that registered it (decision 0006), proves
 * nothing: whoever wrote the object wrote its claims, and asking it for an "iss" would ask a forger to
 * name himself. OIDC Core §6.1 makes them optional for exactly that kind of object, and the "client_id"
 * rule, which the query decides and not the object, is asked of both.
 */
final readonly class RequestObjectValidator
{
    /**
     * @param DateInterval $maximumLifetime how long a request object may stand, from its "nbf"
     * @param DateInterval $leeway what is allowed of the clock of the client, both ways
     */
    public function __construct(
        public DateInterval $maximumLifetime,
        private DateInterval $leeway,
    ) {
    }

    /**
     * @throws InvalidRequestObjectException
     */
    public function validate(RequestObject $object, Client $client, Tenant $tenant, DateTimeImmutable $now): void
    {
        $jwt = $object->jwt;
        $clientId = $jwt->claim('client_id');
        if ($clientId !== null && $clientId !== $client->registration->clientId) {
            throw new InvalidRequestObjectException('The client_id inside a request object is the one the request names outside it (OIDC Core section 6.1).');
        }
        if (! $object->isSigned()) {
            return;
        }
        if ($jwt->claim('iss') !== $client->registration->clientId) {
            throw new InvalidRequestObjectException('The iss of a request object names the client that sends it (RFC 9101 section 4).');
        }
        if (! in_array($tenant->issuer->value, $jwt->audiences(), true)) {
            throw new InvalidRequestObjectException('The aud of a request object names the issuer of this provider (RFC 9101 section 4).');
        }
        $notBefore = $jwt->time('nbf');
        if ($notBefore === null) {
            throw new InvalidRequestObjectException('A request object carries an nbf (RFC 9101 section 4).');
        }
        if ($notBefore > $now->add($this->leeway)) {
            throw new InvalidRequestObjectException('The request object is not valid yet.');
        }
        $expiresAt = $jwt->time('exp');
        if ($expiresAt === null) {
            throw new InvalidRequestObjectException('A request object carries an exp (RFC 9101 section 4).');
        }
        if ($expiresAt <= $now->sub($this->leeway)) {
            throw new InvalidRequestObjectException('The request object has expired.');
        }
        if ($expiresAt > $notBefore->add($this->maximumLifetime)) {
            throw new InvalidRequestObjectException('The exp of a request object stays inside the lifetime this provider accepts.');
        }
    }
}

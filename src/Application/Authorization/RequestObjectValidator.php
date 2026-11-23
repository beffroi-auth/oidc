<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Authorization\RequestObject;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Exception\InvalidRequestObjectException;
use function in_array;

/**
 * RFC 9101 §6.1, OIDC Core §6.1
 *
 * An unsigned object proves nothing, so of its claims only "client_id" is checked.
 */
final readonly class RequestObjectValidator
{
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
        if ($jwt->startsAfter($now->add($this->leeway))) {
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

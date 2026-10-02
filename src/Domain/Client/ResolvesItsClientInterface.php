<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Core\Domain\Tenant\Tenant;

/**
 * A record the provider keeps for a client it does not keep with it (architecture §4.1): what is stored
 * is the identifier the client registered under, and the registration itself is read back from wherever
 * registrations are read, at every load. A record that works that way declares it here, and whatever puts
 * the client back reads this one declaration instead of naming the records it knows of.
 *
 * Where the client is held is part of what is declared, because it is not the same place for all of them:
 * an interaction holds it on the authorization request it parked, and every other record holds it on
 * itself. A record whose client could not be resolved keeps that property uninitialised, which is how a
 * row of a client no longer registered is told from one of a client still served.
 */
interface ResolvesItsClientInterface
{
    public Tenant $tenant { get; }

    /**
     * The identifier of the client, as the record kept it.
     */
    public string $clientId { get; }

    /**
     * The object whose "client" property carries the registration: the record itself, or the value object
     * it keeps the request on.
     */
    public function clientHolder(): object;
}

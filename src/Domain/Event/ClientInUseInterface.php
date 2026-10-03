<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

/**
 * An event that says somebody is using a client of this provider. There are two things that mean it, and
 * they are the two the event of each announces: an authorization granted for that client, and a request it
 * made at the token endpoint. Nothing else does: a client that registered itself and never came back has
 * used nothing, and a client whose requests are all refused has used nothing either.
 *
 * What reads it is the date a stored client carries of its last use, and the removal that follows from it
 * (decision 0009). A third thing that came to mean the same would be this interface on one more event and
 * nothing else edited; what makes that safe is that the date only ever moves forward.
 */
interface ClientInUseInterface extends ConcernsAClientInterface
{
}

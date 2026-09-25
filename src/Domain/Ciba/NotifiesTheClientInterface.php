<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Ciba;

/**
 * A delivery mode where the provider calls the client back once the request has been answered (CIBA Core
 * §10.2): the client registers where it is called, sends a token of its own with every request so that
 * it recognises the call, and comes to the token endpoint like a poller once it has been told.
 *
 * A mode that declares this is what makes those two values required of a request and kept on the record;
 * one that does not declare it is answered by polling alone, and the provider keeps neither.
 */
interface NotifiesTheClientInterface extends DeliveryModeInterface
{
}

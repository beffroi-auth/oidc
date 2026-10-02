<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

/**
 * A grant whose user is asked somewhere other than in the client's own browser (RFC 8628 §3.3): the client
 * has no browser to send anywhere, so it starts the flow at an endpoint of its own, shows what the provider
 * answered, and polls the token endpoint until the user has answered elsewhere.
 *
 * A grant declares this instead of anything reading its name: the endpoint where such a flow starts refuses
 * a client registered for none of them, and it is the wiring that says which those are.
 */
interface AsksTheUserOnAnotherDeviceInterface extends GrantInterface
{
}

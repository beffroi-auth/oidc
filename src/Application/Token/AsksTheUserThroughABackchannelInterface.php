<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

/**
 * A grant whose user is asked on a device they already hold, without the client ever having a browser in
 * the flow (CIBA Core §7): the client starts the request at an endpoint of its own, names the user it is
 * for, and waits, by polling or by being called back.
 *
 * It is not the device grant's way of asking somebody elsewhere (AsksTheUserOnAnotherDeviceInterface):
 * there, a code travels from the client's screen to the user, and the endpoint that starts the flow
 * serves whoever asks. Here the provider names the user itself and reaches them, and the two endpoints
 * are told apart by the grants their clients registered, not by anything reading a name.
 */
interface AsksTheUserThroughABackchannelInterface extends GrantInterface
{
}

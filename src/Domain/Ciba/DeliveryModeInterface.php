<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Ciba;

/**
 * How a client is told that the request it made on the back channel has been answered (CIBA Core §10).
 * One class per mode, wired into the provider: what the document announces in
 * "backchannel_token_delivery_modes_supported" (§4) and what a client may register in
 * "backchannel_token_delivery_mode" are that one wired list, and a mode the provider gains is a class
 * added to it rather than a case added to an enumeration.
 *
 * What a mode does beside naming itself, it declares by the interfaces it implements next to this one:
 * a mode that calls the client back says so (NotifiesTheClientInterface), and nothing anywhere reads a
 * mode by its name to find out.
 */
interface DeliveryModeInterface
{
    /**
     * The name of §4 and of §7.1, compared byte for byte.
     */
    public function name(): string;
}

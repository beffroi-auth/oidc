<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateInterval;

/**
 * How long a logout token stays on its way to a client (Back-Channel Logout 1.0 §2.5). The provider mints
 * one, hands it to what carries it and never sees it again, so what bounds its life is the patience of
 * the sender: how many times a send that did not reach its client is tried again, and how long each
 * attempt is given. The integration wires that patience, so it says it. Two things read it here rather
 * than from the same numbers written a second time (issue #155): the "exp" of the token, which §2.4
 * requires and which is the end of that patience, and the retirement of the signing key, held back for
 * exactly as long.
 */
interface LogoutTokenDeliveryInterface
{
    /**
     * The longest a logout token may still reach a client after it was minted.
     */
    public function deliveryBudget(): DateInterval;
}

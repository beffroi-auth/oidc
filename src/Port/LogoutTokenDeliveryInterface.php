<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateInterval;

/**
 * How long a logout token stays on its way to a client (Back-Channel Logout 1.0 §2.5). The provider mints
 * one, hands it to what carries it and never sees it again; it carries no "exp", RFC 8417 §2.2 not
 * recommending one on a security event token, so what bounds its life is the patience of the sender: how
 * many times a send that did not reach its client is tried again, and how long each attempt is given. The
 * integration wires that patience, so it says, and the retirement of a signing key reads it here rather
 * than from the same numbers written a second time (issue #155).
 */
interface LogoutTokenDeliveryInterface
{
    /**
     * The longest a logout token may still reach a client after it was minted.
     */
    public function deliveryBudget(): DateInterval;
}

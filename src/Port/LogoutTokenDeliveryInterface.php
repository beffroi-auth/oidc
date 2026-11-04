<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateInterval;

interface LogoutTokenDeliveryInterface
{
    /**
     * The longest a logout token may still reach a client after it was minted.
     */
    public function deliveryBudget(): DateInterval;
}

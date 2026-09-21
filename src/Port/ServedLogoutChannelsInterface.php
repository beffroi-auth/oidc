<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\EndSession\LogoutChannel;

/**
 * The ways of telling a client that a session ended the provider actually serves; the integration wires
 * one thing per channel, so it says. What the discovery document announces reads this one source, so
 * that the document cannot promise a channel nothing serves (issue #98).
 */
interface ServedLogoutChannelsInterface
{
    /**
     * @return list<LogoutChannel> empty when a deployment tells no client anything
     */
    public function servedLogoutChannels(): array;
}

<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\EndSession\LogoutChannel;

interface ServedLogoutChannelsInterface
{
    /**
     * @return list<LogoutChannel>
     */
    public function servedLogoutChannels(): array;
}

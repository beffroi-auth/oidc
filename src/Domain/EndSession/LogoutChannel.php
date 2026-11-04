<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\EndSession;

enum LogoutChannel: string
{
    case BackChannel = 'back_channel';

    case FrontChannel = 'front_channel';
}

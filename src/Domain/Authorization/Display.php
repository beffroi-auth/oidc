<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

/**
 * OIDC Core §3.1.2.1
 */
enum Display: string
{
    case Page = 'page';
    case Popup = 'popup';
    case Touch = 'touch';
    case Wap = 'wap';
}

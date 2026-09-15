<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

/**
 * OIDC Core §3.1.2.1 "display": how the client would like the interaction to be rendered. A hint kept for
 * the integration; the provider may render otherwise.
 */
enum Display: string
{
    case Page = 'page';
    case Popup = 'popup';
    case Touch = 'touch';
    case Wap = 'wap';
}

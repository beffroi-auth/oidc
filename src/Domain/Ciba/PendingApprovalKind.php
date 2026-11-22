<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Ciba;

use Beffroi\Core\Domain\Notification\ChoosableNotificationKindInterface;

/**
 * CIBA Core §7
 *
 * A request waiting for the person to approve it reaches them by the channels they chose.
 */
final readonly class PendingApprovalKind implements ChoosableNotificationKindInterface
{
    public const string NAME = 'pending_approval';

    public function name(): string
    {
        return self::NAME;
    }
}

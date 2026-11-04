<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Ciba;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

/**
 * CIBA Core §7, BCP 10027 §5.2
 *
 * It carries no identifier and no link: one that leads straight into an approval is the attack BCP 10027 describes.
 */
final readonly class PendingApproval
{
    public function __construct(
        public Tenant $tenant,
        public Uuid $userId,
        public string $clientName,
        public ?BindingMessage $bindingMessage,
        public DateTimeImmutable $expiresAt,
        public string $approvalUri,
    ) {
    }
}

<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Ciba;

use DateTimeImmutable;
use Heidi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

/**
 * What the provider has to tell a user so that they come and answer a request made for them on the back
 * channel (CIBA Core §7, BCP 10027 §5.2): who is asking, what they wrote beside it, until when it is
 * worth answering, and where the provider takes an answer.
 *
 * It carries no identifier of the request and no link that answers one. A notification that could be
 * followed straight into an approval is the cross-device attack BCP 10027 is written about: what reaches
 * the user says that something is waiting, and the user goes to the provider they already know and finds
 * it there. It is also what survives a queue, being names and dates and nothing that has to be resolved
 * again on the other side.
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

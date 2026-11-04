<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Disclosure;

use Beffroi\Core\Port\UuidGeneratorInterface;
use Beffroi\Oidc\Domain\Disclosure\Disclosure;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use Beffroi\Oidc\Port\DisclosuresInterface;

final readonly class DisclosureRecording
{
    public function __construct(
        private DisclosuresInterface $disclosures,
        private UuidGeneratorInterface $uuids,
    ) {
    }

    public function record(TokensIssued $act): void
    {
        $subject = $act->subject();
        if ($subject === null) {
            return;
        }
        $this->disclosures->record(new Disclosure(
            $this->uuids->timeOrdered(),
            $act->tenant,
            $subject,
            $act->clientId,
            $act->name(),
            $act->occurredAt,
            $act->grantedScopes,
            $act->claimsRequest,
            $act->authorizationDetails,
            $act->tokenShape,
        ));
    }
}

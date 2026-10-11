<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Disclosure;

use Beffroi\Core\Port\UuidGeneratorInterface;
use Beffroi\Oidc\Domain\Disclosure\Disclosure;
use Beffroi\Oidc\Domain\Event\TokensIssued;
use Beffroi\Oidc\Port\DisclosuresInterface;

/**
 * Writes down what a client was given of a person (issue #590), out of the act that gave it and out of
 * nothing else: the grant is not read a second time, and no store is asked what the request had asked for.
 *
 * It draws the identifier, so nothing above it decides what a row is called: a UUIDv7, which sorts
 * chronologically, as `ActRecording` draws the identifier of the act this row sits beside.
 *
 * **What was given to nobody is written nowhere.** A client that obtained tokens for itself was given
 * nothing of anybody (RFC 6749 §4.4), and the act of it names no person, so there is no register of a
 * person for the row to belong to.
 *
 * It is done on the lane the events travel and therefore after the request that raised it: nothing of the
 * protocol waits for this write, and a row that could not be written does not undo what was done.
 */
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

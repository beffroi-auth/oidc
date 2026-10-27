<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Exception\UnreadableClientMetadataException;

/**
 * One kind of "sub" (OIDC Core §8), both ways round: the identifier a client of this kind sees for a user,
 * in one step or in two, and the user a "sub" of this kind names for that client. It names itself, which is the
 * name a client registers in "subject_type" (OIDC Registration §2) and the name the discovery document announces.
 *
 * What picks it for a client is AssignedSubjectIdentifiers, and it is picked by that name alone: nothing
 * reads a class, and a kind added to a deployment is a class and one line in the wiring.
 */
interface SubjectIdentifierKindInterface extends SubjectIdentifierResolverInterface, SubjectIdentifierOpenerInterface, PresentedSubjectReaderInterface
{
    /**
     * @return non-empty-string
     */
    public function subjectType(): string;

    /**
     * What this kind needs of a registration beyond naming it, checked where a registration meets the wiring
     * and never at issuance: a kind computed from something a client registers refuses a client that
     * registered no such thing, rather than serving it an identifier drawn from something else (OIDC Core
     * §8.1).
     *
     * @throws UnreadableClientMetadataException when no "sub" of this kind can be assigned to this client
     */
    public function assertAssignable(ClientRegistration $registration): void;
}
